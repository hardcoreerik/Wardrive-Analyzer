package com.wardrive.analyzer.android.ingest

import java.io.BufferedInputStream
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.math.min

data class PcapSummary(
    val packetCount: Int,
    val eapolCount: Int,
    val totalBytes: Long,
    val apCount: Int,
    val stationCount: Int,
    val managementFrameCount: Int,
    val handshakeConfidence: String
)

class PcapIngestService {
    fun summarize(inputStream: InputStream): PcapSummary {
        val stream = BufferedInputStream(inputStream)
        val header = ByteArray(24)
        if (stream.read(header) != 24) {
            return PcapSummary(0, 0, 0, 0, 0, 0, "NONE")
        }

        val order = when {
            header[0] == 0xa1.toByte() && header[1] == 0xb2.toByte() && header[2] == 0xc3.toByte() && header[3] == 0xd4.toByte() -> ByteOrder.BIG_ENDIAN
            header[0] == 0xd4.toByte() && header[1] == 0xc3.toByte() && header[2] == 0xb2.toByte() && header[3] == 0xa1.toByte() -> ByteOrder.LITTLE_ENDIAN
            else -> ByteOrder.LITTLE_ENDIAN
        }

        val network = ByteBuffer.wrap(header, 20, 4).order(order).int

        var packetCount = 0
        var eapolCount = 0
        var totalBytes = 24L
        var managementFrameCount = 0
        val apSet = linkedSetOf<String>()
        val stationSet = linkedSetOf<String>()
        val eapolMessages = linkedSetOf<Int>()

        val pktHeader = ByteArray(16)
        while (true) {
            val readHeader = stream.read(pktHeader)
            if (readHeader < 16) break
            totalBytes += 16
            val inclLen = ByteBuffer.wrap(pktHeader, 8, 4).order(order).int
            if (inclLen <= 0 || inclLen > 10_000_000) break
            val payload = ByteArray(inclLen)
            val readPayload = stream.read(payload)
            if (readPayload != inclLen) break

            totalBytes += inclLen.toLong()
            packetCount += 1

            if (containsEapol(payload)) {
                eapolCount += 1
                detectHandshakeMessage(payload)?.let { eapolMessages += it }
            }

            val frame = extractDot11Frame(payload, network) ?: continue
            val parsed = parseManagementAddresses(frame)
            if (parsed != null) {
                managementFrameCount += 1
                parsed.bssid?.let { apSet += it }
                parsed.station?.let { stationSet += it }
            }
        }

        return PcapSummary(
            packetCount = packetCount,
            eapolCount = eapolCount,
            totalBytes = totalBytes,
            apCount = apSet.size,
            stationCount = stationSet.size,
            managementFrameCount = managementFrameCount,
            handshakeConfidence = handshakeConfidence(eapolCount, eapolMessages)
        )
    }

    private data class Dot11Info(val bssid: String?, val station: String?)

    private fun extractDot11Frame(payload: ByteArray, network: Int): ByteArray? {
        return when (network) {
            105 -> payload // DLT_IEEE802_11
            127 -> { // DLT_IEEE802_11_RADIO (radiotap)
                if (payload.size < 4) return null
                val rtLen = ((payload[2].toInt() and 0xFF) or ((payload[3].toInt() and 0xFF) shl 8))
                if (rtLen <= 0 || rtLen >= payload.size) return null
                payload.copyOfRange(rtLen, payload.size)
            }
            else -> null
        }
    }

    private fun parseManagementAddresses(frame: ByteArray): Dot11Info? {
        if (frame.size < 24) return null

        val fc = (frame[0].toInt() and 0xFF) or ((frame[1].toInt() and 0xFF) shl 8)
        val type = (fc shr 2) and 0x3
        if (type != 0) return null

        val subtype = (fc shr 4) and 0xF
        val addr2 = macToString(frame, 10)
        val addr3 = macToString(frame, 16)

        return when (subtype) {
            8, 5 -> Dot11Info(bssid = addr3, station = null) // beacon/probe response
            4, 0, 2 -> Dot11Info(bssid = addr3, station = addr2) // probe/assoc/reassoc request
            else -> Dot11Info(bssid = addr3, station = null)
        }
    }

    private fun macToString(frame: ByteArray, offset: Int): String {
        val end = min(offset + 6, frame.size)
        val bytes = frame.copyOfRange(offset, end)
        if (bytes.size < 6) return ""
        return bytes.joinToString(":") { b -> "%02X".format(b.toInt() and 0xFF) }
    }

    private fun containsEapol(data: ByteArray): Boolean {
        if (data.size < 2) return false
        for (i in 0 until data.size - 1) {
            if (data[i] == 0x88.toByte() && data[i + 1] == 0x8e.toByte()) {
                return true
            }
        }
        return false
    }

    private fun detectHandshakeMessage(data: ByteArray): Int? {
        for (i in 0 until data.size - 8) {
            if (data[i] != 0x88.toByte() || data[i + 1] != 0x8e.toByte()) continue
            val eapolStart = i + 2
            if (eapolStart + 7 >= data.size) continue
            val eapolType = data[eapolStart + 1].toInt() and 0xFF
            if (eapolType != 3) continue
            val keyInfo = ((data[eapolStart + 5].toInt() and 0xFF) shl 8) or
                (data[eapolStart + 6].toInt() and 0xFF)

            val install = (keyInfo and 0x0040) != 0
            val ack = (keyInfo and 0x0080) != 0
            val mic = (keyInfo and 0x0100) != 0
            val secure = (keyInfo and 0x0200) != 0

            if (ack && !mic) return 1
            if (!ack && mic && !secure) return 2
            if (ack && mic && install) return 3
            if (!ack && mic && secure) return 4
        }
        return null
    }

    private fun handshakeConfidence(eapolCount: Int, msgs: Set<Int>): String {
        if (eapolCount <= 0) return "NONE"
        return when {
            msgs.containsAll(setOf(1, 2, 3, 4)) -> "4WAY"
            msgs.isNotEmpty() -> "PARTIAL"
            else -> "EAPOL"
        }
    }
}
