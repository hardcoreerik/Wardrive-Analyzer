package com.wardrive.analyzer.android.ui.screens

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Badge
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.graphics.Color
import androidx.compose.foundation.Canvas
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.wardrive.analyzer.android.data.model.MarauderApRecordEntity
import com.wardrive.analyzer.android.marauder.MarauderConnectionStatus
import com.wardrive.analyzer.android.marauder.MarauderConnectionUiState
import com.wardrive.analyzer.android.marauder.MarauderMascotState

@Composable
fun MarauderLiveScreen(
    modifier: Modifier = Modifier,
    state: MarauderConnectionUiState,
    terminalLines: List<String>,
    apRecords: List<MarauderApRecordEntity>,
    diagnostics: List<String>,
    lastCommand: String,
    mascotMessage: String,
    mascotState: MarauderMascotState,
    onRefresh: () -> Unit,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
    onSendCommand: (String) -> Unit,
    onSaveLog: () -> Unit,
    onShareDiagnostics: () -> Unit,
    onExportApCsv: () -> Unit
) {
    var command by remember { mutableStateOf("") }
    val quickCommands = listOf("help", "scanap", "listap", "stopscan", "wardrive", "status")

    LazyColumn(
        modifier = modifier.fillMaxSize().padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        item {
            Text("MARAUDER LIVE", style = MaterialTheme.typography.headlineMedium, color = MaterialTheme.colorScheme.primary)
            Text(statusText(state), style = MaterialTheme.typography.bodyMedium)
        }
        item {
            Card {
                Row(
                    Modifier.fillMaxWidth().padding(12.dp),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    MarauderPixelSprite(
                        state = mascotState,
                        modifier = Modifier.size(72.dp)
                    )
                    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Text("Marauder Brief", style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.secondary)
                        Text(mascotMessage)
                        if (lastCommand.isNotBlank()) {
                            Badge { Text("Last Command: $lastCommand") }
                        }
                    }
                }
            }
        }
        item {
            Card {
                Column(Modifier.fillMaxWidth().padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("USB Serial", style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.secondary)
                    Text("Status: ${state.status.name.lowercase()} - ${state.message}")
                    val device = state.device
                    Text("Device: ${device?.deviceName ?: "No Marauder connected"}")
                    Text("VID: ${device?.vendorId ?: "?"}  PID: ${device?.productId ?: "?"}  Driver: ${device?.driverName ?: "?"}")
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.horizontalScroll(rememberScrollState())) {
                        Button(onClick = onRefresh) { Text("Refresh") }
                        Button(
                            onClick = onConnect,
                            enabled = state.status != MarauderConnectionStatus.CONNECTED && state.status != MarauderConnectionStatus.CONNECTING
                        ) { Text(if (state.status == MarauderConnectionStatus.PERMISSION_REQUIRED) "Grant / Connect" else "Connect") }
                        Button(
                            onClick = onDisconnect,
                            enabled = state.status == MarauderConnectionStatus.CONNECTED || state.status == MarauderConnectionStatus.ERROR
                        ) { Text("Disconnect") }
                        Button(onClick = onSaveLog, enabled = terminalLines.isNotEmpty()) { Text("Save Log") }
                        Button(onClick = onShareDiagnostics) { Text("Share Diagnostics") }
                    }
                }
            }
        }
        item {
            Card {
                Column(Modifier.fillMaxWidth().padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Command", style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.secondary)
                    OutlinedTextField(
                        value = command,
                        onValueChange = { command = it },
                        label = { Text("Manual CLI command") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.horizontalScroll(rememberScrollState())) {
                        Button(
                            onClick = {
                                onSendCommand(command)
                                command = ""
                            },
                            enabled = command.isNotBlank() && state.status == MarauderConnectionStatus.CONNECTED
                        ) { Text("Send") }
                        quickCommands.forEach { quick ->
                            Button(
                                onClick = { onSendCommand(quick) },
                                enabled = state.status == MarauderConnectionStatus.CONNECTED
                            ) { Text(quick) }
                        }
                    }
                }
            }
        }
        item {
            Text("Live Terminal", style = MaterialTheme.typography.titleMedium)
            Card {
                Column(Modifier.fillMaxWidth().height(260.dp).padding(10.dp)) {
                    if (terminalLines.isEmpty()) {
                        Text("No parsed records yet - raw serial and diagnostics are still saved when data arrives.")
                    } else {
                        val visible = terminalLines.takeLast(90).joinToString("\n")
                        Text(visible, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
        item {
            val strongest = apRecords.mapNotNull { it.rssi }.maxOrNull()
            val channels = apRecords.mapNotNull { it.channel }.toSet().sorted()
            Card {
                Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text("Marauder Explain", style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.secondary)
                    Text("What happened: ${if (apRecords.isEmpty()) "No AP parse hits yet." else "Parsed ${apRecords.size} AP rows from live stream."}")
                    Text("Why it matters: RSSI near 0 is stronger. Channel spread hints band usage and overlap.")
                    Text("Safe next step: capture baseline with `status`, then run `scanap`, and stop with `stopscan` when done.")
                    Text("Signals: strongest RSSI=${strongest ?: "?"}; channels=${if (channels.isEmpty()) "none" else channels.joinToString(",")}")
                    if (apRecords.any { it.ssid == "<unknown>" || it.rssi == null || it.encryption.isNullOrBlank() }) {
                        Text("Parsing uncertainty: some fields stayed unknown, but raw terminal output is preserved.", style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.horizontalScroll(rememberScrollState())) {
                Text("Parsed APs: ${apRecords.size}", style = MaterialTheme.typography.titleMedium)
                Button(onClick = onExportApCsv, enabled = apRecords.isNotEmpty()) { Text("Export AP CSV") }
            }
        }
        items(apRecords.take(50), key = { it.id }) { ap ->
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp)) {
                    Text(ap.ssid, style = MaterialTheme.typography.titleMedium)
                    Text("${ap.bssid}  ch=${ap.channel ?: "?"}  rssi=${ap.rssi ?: "?"}")
                    Text("Auth: ${ap.encryption ?: "unknown"}")
                }
            }
        }
        item {
            Spacer(Modifier.height(8.dp))
            Text("Diagnostics", style = MaterialTheme.typography.titleMedium)
            Card {
                Text(
                    diagnostics.takeLast(20).joinToString("\n"),
                    modifier = Modifier.fillMaxWidth().padding(10.dp),
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }
    }
}

@Composable
private fun MarauderPixelSprite(
    state: MarauderMascotState,
    modifier: Modifier = Modifier
) {
    val glow = when (state) {
        MarauderMascotState.CONNECT -> Color(0xFF00F5D4)
        MarauderMascotState.SCAN -> Color(0xFF00C8FF)
        MarauderMascotState.EXPORT -> Color(0xFFFFC857)
        MarauderMascotState.SYNC -> Color(0xFF78FF85)
        MarauderMascotState.WARNING -> Color(0xFFFF6B6B)
        MarauderMascotState.SUCCESS -> Color(0xFF00FFA8)
    }
    val matrix = spriteFor(state)
    Box(modifier = modifier) {
        Canvas(modifier = Modifier.fillMaxSize()) {
            val rows = matrix.size
            val cols = matrix.firstOrNull()?.length ?: 1
            val cellW = size.width / cols
            val cellH = size.height / rows
            matrix.forEachIndexed { y, row ->
                row.forEachIndexed { x, c ->
                    if (c == '#') {
                        drawRoundRect(
                            color = glow,
                            topLeft = androidx.compose.ui.geometry.Offset(x * cellW, y * cellH),
                            size = androidx.compose.ui.geometry.Size(cellW * 0.9f, cellH * 0.9f),
                            cornerRadius = CornerRadius(2f, 2f)
                        )
                    }
                }
            }
        }
    }
}

private fun spriteFor(state: MarauderMascotState): List<String> =
    when (state) {
        MarauderMascotState.CONNECT -> listOf(
            "....##....",
            "...####...",
            "..######..",
            "..##..##..",
            ".##.##.##.",
            ".########.",
            "..##..##..",
            "..#....#.."
        )
        MarauderMascotState.SCAN -> listOf(
            "...####...",
            "..##..##..",
            ".##.##.##.",
            ".########.",
            "..######..",
            "..##..##..",
            ".##....##.",
            "#..####..#"
        )
        MarauderMascotState.EXPORT -> listOf(
            "...####...",
            "..######..",
            ".##....##.",
            ".##.##.##.",
            ".########.",
            "..##..##..",
            "...####...",
            "....##...."
        )
        MarauderMascotState.SYNC -> listOf(
            "....##....",
            "...####...",
            "..##..##..",
            ".##.##.##.",
            ".########.",
            ".##....##.",
            "..######..",
            "...#..#..."
        )
        MarauderMascotState.WARNING -> listOf(
            "....##....",
            "...####...",
            "..##..##..",
            ".##....##.",
            ".##....##.",
            "..##..##..",
            "...####...",
            "....##...."
        )
        MarauderMascotState.SUCCESS -> listOf(
            "....##....",
            "...####...",
            "..######..",
            ".##....##.",
            ".##.##.##.",
            "..######..",
            "...####...",
            "....##...."
        )
    }

private fun statusText(state: MarauderConnectionUiState): String =
    when (state.status) {
        MarauderConnectionStatus.DISCONNECTED -> "No Marauder connected"
        MarauderConnectionStatus.PERMISSION_REQUIRED -> "USB permission needed"
        MarauderConnectionStatus.CONNECTING -> "Connecting at 115200"
        MarauderConnectionStatus.CONNECTED -> "Connected at 115200"
        MarauderConnectionStatus.ERROR -> "Connection error"
    }
