package com.wardrive.analyzer.android.ui.screens

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.wardrive.analyzer.android.data.model.MarauderImportedFileEntity
import com.wardrive.analyzer.android.data.model.MarauderWardriveRecordEntity

@Composable
fun MarauderImportsScreen(
    modifier: Modifier = Modifier,
    imports: List<MarauderImportedFileEntity>,
    wardriveRecords: List<MarauderWardriveRecordEntity>,
    status: String,
    onPickFiles: () -> Unit,
    onPickFolder: () -> Unit,
    onExportCsv: () -> Unit,
    onExportJson: () -> Unit,
    onShareFile: (MarauderImportedFileEntity) -> Unit
) {
    val uniqueBssids = wardriveRecords.mapNotNull { it.bssid }.toSet().size
    val strongest = wardriveRecords.mapNotNull { it.rssi }.maxOrNull()
    val channels = wardriveRecords.mapNotNull { it.channel }.toSet().sorted()
    val gpsCount = wardriveRecords.count { it.latitude != null && it.longitude != null }

    LazyColumn(
        modifier = modifier.fillMaxSize().padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        item {
            Text("MARAUDER FILES", style = MaterialTheme.typography.headlineMedium, color = MaterialTheme.colorScheme.primary)
            Text(status)
        }
        item {
            Card {
                Column(Modifier.fillMaxWidth().padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Import Marauder Files", style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.secondary)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.horizontalScroll(rememberScrollState())) {
                        Button(onClick = onPickFiles) { Text("Pick Files") }
                        Button(onClick = onPickFolder) { Text("Pick Folder") }
                        Button(onClick = onExportCsv, enabled = wardriveRecords.isNotEmpty()) { Text("Export CSV") }
                        Button(onClick = onExportJson, enabled = wardriveRecords.isNotEmpty()) { Text("Export JSON") }
                    }
                }
            }
        }
        item {
            Card {
                Column(Modifier.fillMaxWidth().padding(14.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("Parsed Records", style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.secondary)
                    Text("APs: ${wardriveRecords.size}  Unique BSSIDs: $uniqueBssids")
                    Text("Strongest signal: ${strongest ?: "?"}  GPS points: $gpsCount")
                    Text("Channels seen: ${if (channels.isEmpty()) "none" else channels.joinToString(", ")}")
                }
            }
        }
        item {
            Text("Imported Files (${imports.size})", style = MaterialTheme.typography.titleMedium)
        }
        items(imports, key = { it.importId }) { item ->
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(item.originalName, style = MaterialTheme.typography.titleMedium)
                    Text("${item.fileType}  ${item.sizeBytes} bytes")
                    Text("SHA-256: ${item.sha256.take(16)}...")
                    Text("Parsed ${item.parsedRecordCount} records")
                    Button(onClick = { onShareFile(item) }) { Text("Share File") }
                }
            }
        }
        item {
            Text("Recent Wardrive Records", style = MaterialTheme.typography.titleMedium)
        }
        items(wardriveRecords.take(80), key = { it.id }) { record ->
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp)) {
                    Text(record.ssid ?: "<unknown>", style = MaterialTheme.typography.titleMedium)
                    Text("${record.bssid ?: "no bssid"}  ch=${record.channel ?: "?"}  rssi=${record.rssi ?: "?"}")
                    Text("GPS: ${record.latitude ?: "?"}, ${record.longitude ?: "?"}")
                }
            }
        }
    }
}
