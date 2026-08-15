package com.wardrive.analyzer.android.usb

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbDeviceConnection
import android.hardware.usb.UsbManager
import android.os.Build
import android.util.Log
import androidx.core.content.ContextCompat
import com.hoho.android.usbserial.driver.UsbSerialPort
import com.hoho.android.usbserial.driver.UsbSerialProber
import com.hoho.android.usbserial.util.SerialInputOutputManager
import com.wardrive.analyzer.android.marauder.MarauderConnectionStatus
import com.wardrive.analyzer.android.marauder.MarauderConnectionUiState
import com.wardrive.analyzer.android.marauder.MarauderDeviceInfo
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class MarauderUsbSerialManager(
    private val context: Context,
    private val scope: CoroutineScope,
    private val onData: (String) -> Unit,
    private val onConnected: (MarauderDeviceInfo) -> Unit,
    private val onDiagnostic: (String) -> Unit
) {
    private val tag = "MarauderUsbSerial"
    private val usbManager = context.getSystemService(Context.USB_SERVICE) as UsbManager
    private val _state = MutableStateFlow(MarauderConnectionUiState())
    val state: StateFlow<MarauderConnectionUiState> = _state.asStateFlow()

    private var port: UsbSerialPort? = null
    private var connection: UsbDeviceConnection? = null
    private var ioManager: SerialInputOutputManager? = null
    private var receiverRegistered = false

    private val usbReceiver = object : BroadcastReceiver() {
        override fun onReceive(ctx: Context, intent: Intent) {
            when (intent.action) {
                ACTION_USB_PERMISSION -> {
                    val device = usbDeviceExtra(intent)
                    val granted = intent.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false)
                    if (granted && device != null) {
                        diagnostic("USB permission granted for ${device.deviceName}")
                        openDevice(device)
                    } else {
                        diagnostic("USB permission denied")
                        _state.value = MarauderConnectionUiState(
                            status = MarauderConnectionStatus.ERROR,
                            device = device?.toInfo(),
                            message = "USB permission denied"
                        )
                    }
                }
                UsbManager.ACTION_USB_DEVICE_DETACHED -> {
                    val device = usbDeviceExtra(intent)
                    diagnostic("USB device detached: ${device?.deviceName ?: "unknown"}")
                    close(updateState = true)
                }
                UsbManager.ACTION_USB_DEVICE_ATTACHED -> {
                    val device = usbDeviceExtra(intent)
                    diagnostic("USB device discovered: ${device?.deviceName ?: "unknown"}")
                    refreshDevice()
                }
            }
        }
    }

    fun refreshDevice() {
        registerReceiver()
        val driver = UsbSerialProber.getDefaultProber().findAllDrivers(usbManager).firstOrNull()
        val device = driver?.device
        _state.value = if (device == null) {
            MarauderConnectionUiState(
                status = MarauderConnectionStatus.DISCONNECTED,
                device = null,
                message = "No Marauder connected"
            )
        } else {
            val info = device.toInfo(driver.javaClass.simpleName)
            diagnostic("USB serial device discovered: ${info.deviceName} vid=${info.vendorId} pid=${info.productId}")
            MarauderConnectionUiState(
                status = if (usbManager.hasPermission(device)) MarauderConnectionStatus.DISCONNECTED else MarauderConnectionStatus.PERMISSION_REQUIRED,
                device = info,
                message = if (usbManager.hasPermission(device)) "Marauder serial device detected" else "USB permission needed"
            )
        }
    }

    fun connect() {
        registerReceiver()
        val driver = UsbSerialProber.getDefaultProber().findAllDrivers(usbManager).firstOrNull()
        if (driver == null) {
            diagnostic("No USB serial driver found")
            _state.value = MarauderConnectionUiState(
                status = MarauderConnectionStatus.DISCONNECTED,
                message = "No Marauder connected"
            )
            return
        }
        val device = driver.device
        if (!usbManager.hasPermission(device)) {
            diagnostic("Requesting USB permission for ${device.deviceName}")
            _state.value = MarauderConnectionUiState(
                status = MarauderConnectionStatus.PERMISSION_REQUIRED,
                device = device.toInfo(driver.javaClass.simpleName),
                message = "USB permission needed"
            )
            usbManager.requestPermission(device, permissionIntent())
            return
        }
        openDevice(device)
    }

    fun writeCommand(command: String) {
        val clean = command.trim()
        if (clean.isBlank()) return
        val activePort = port
        if (activePort == null) {
            diagnostic("Command ignored while disconnected: $clean")
            return
        }
        scope.launch(Dispatchers.IO) {
            try {
                activePort.write((clean + "\r\n").toByteArray(Charsets.UTF_8), WRITE_TIMEOUT_MS)
                diagnostic("Command sent: $clean")
            } catch (e: Exception) {
                Log.e(tag, "Serial write failed", e)
                diagnostic("Serial write error: ${e.message ?: e.javaClass.simpleName}")
                _state.value = _state.value.copy(
                    status = MarauderConnectionStatus.ERROR,
                    message = "Serial write error"
                )
            }
        }
    }

    fun close(updateState: Boolean = true) {
        try {
            ioManager?.stop()
        } catch (_: Exception) {
        }
        ioManager = null
        try {
            port?.close()
        } catch (_: Exception) {
        }
        port = null
        try {
            connection?.close()
        } catch (_: Exception) {
        }
        connection = null
        if (updateState) {
            diagnostic("Serial port closed")
            _state.value = MarauderConnectionUiState(
                status = MarauderConnectionStatus.DISCONNECTED,
                device = _state.value.device,
                message = "Disconnected"
            )
        }
    }

    fun dispose() {
        close(updateState = true)
        if (receiverRegistered) {
            try {
                context.unregisterReceiver(usbReceiver)
            } catch (_: Exception) {
            }
            receiverRegistered = false
        }
    }

    private fun openDevice(device: UsbDevice) {
        close(updateState = false)
        val driver = UsbSerialProber.getDefaultProber().probeDevice(device)
        if (driver == null || driver.ports.isEmpty()) {
            diagnostic("No serial port found on ${device.deviceName}")
            _state.value = MarauderConnectionUiState(
                status = MarauderConnectionStatus.ERROR,
                device = device.toInfo(),
                message = "No serial port found"
            )
            return
        }
        _state.value = MarauderConnectionUiState(
            status = MarauderConnectionStatus.CONNECTING,
            device = device.toInfo(driver.javaClass.simpleName),
            message = "Connecting at 115200"
        )
        scope.launch(Dispatchers.IO) {
            try {
                val newConnection = usbManager.openDevice(device)
                if (newConnection == null) {
                    _state.value = _state.value.copy(
                        status = MarauderConnectionStatus.ERROR,
                        message = "Could not open USB device"
                    )
                    diagnostic("USB openDevice returned null")
                    return@launch
                }
                val newPort = driver.ports.first()
                newPort.open(newConnection)
                newPort.setParameters(
                    115200,
                    8,
                    UsbSerialPort.STOPBITS_1,
                    UsbSerialPort.PARITY_NONE
                )
                try {
                    newPort.dtr = false
                    newPort.rts = false
                    diagnostic("Serial DTR/RTS cleared to reduce ESP32 reset loops")
                } catch (e: Exception) {
                    diagnostic("Could not clear DTR/RTS: ${e.message ?: e.javaClass.simpleName}")
                }
                connection = newConnection
                port = newPort
                val listener = object : SerialInputOutputManager.Listener {
                    override fun onNewData(data: ByteArray) {
                        val text = data.toString(Charsets.UTF_8)
                        if (text.isNotBlank()) onData(text)
                    }

                    override fun onRunError(e: Exception) {
                        Log.e(tag, "Serial read failed", e)
                        diagnostic("Serial read error: ${e.message ?: e.javaClass.simpleName}")
                        _state.value = _state.value.copy(
                            status = MarauderConnectionStatus.ERROR,
                            message = "Serial read error"
                        )
                        close(updateState = false)
                    }
                }
                ioManager = SerialInputOutputManager(newPort, listener).also {
                    it.start()
                }
                val info = device.toInfo(driver.javaClass.simpleName)
                diagnostic("Serial port opened at 115200")
                onConnected(info)
                _state.value = MarauderConnectionUiState(
                    status = MarauderConnectionStatus.CONNECTED,
                    device = info,
                    message = "Connected at 115200"
                )
            } catch (e: Exception) {
                Log.e(tag, "Serial open failed", e)
                close(updateState = false)
                diagnostic("Serial open error: ${e.message ?: e.javaClass.simpleName}")
                _state.value = MarauderConnectionUiState(
                    status = MarauderConnectionStatus.ERROR,
                    device = device.toInfo(driver.javaClass.simpleName),
                    message = "Serial open error: ${e.message ?: e.javaClass.simpleName}"
                )
            }
        }
    }

    private fun registerReceiver() {
        if (receiverRegistered) return
        val filter = IntentFilter().apply {
            addAction(ACTION_USB_PERMISSION)
            addAction(UsbManager.ACTION_USB_DEVICE_ATTACHED)
            addAction(UsbManager.ACTION_USB_DEVICE_DETACHED)
        }
        ContextCompat.registerReceiver(
            context,
            usbReceiver,
            filter,
            ContextCompat.RECEIVER_NOT_EXPORTED
        )
        receiverRegistered = true
    }

    private fun permissionIntent(): PendingIntent {
        val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) PendingIntent.FLAG_IMMUTABLE else 0
        return PendingIntent.getBroadcast(context, 0, Intent(ACTION_USB_PERMISSION), flags)
    }

    private fun usbDeviceExtra(intent: Intent): UsbDevice? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableExtra(UsbManager.EXTRA_DEVICE, UsbDevice::class.java)
        } else {
            @Suppress("DEPRECATION")
            intent.getParcelableExtra(UsbManager.EXTRA_DEVICE)
        }

    private fun UsbDevice.toInfo(driverName: String? = null): MarauderDeviceInfo =
        MarauderDeviceInfo(
            deviceName = productName ?: deviceName,
            vendorId = vendorId,
            productId = productId,
            driverName = driverName
        )

    private fun diagnostic(message: String) {
        Log.d(tag, message)
        onDiagnostic(message)
    }

    companion object {
        private const val ACTION_USB_PERMISSION = "com.wardrive.analyzer.android.USB_PERMISSION"
        private const val WRITE_TIMEOUT_MS = 2000
    }
}
