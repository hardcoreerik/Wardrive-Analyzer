package com.wardrive.analyzer.android.ui.screens

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.wardrive.analyzer.android.data.model.EvidenceEntity
import java.util.Locale

@Composable
fun EvidenceScreen(
    modifier: Modifier = Modifier,
    items: List<EvidenceEntity>,
    onDeleteSelected: (Set<Long>) -> Unit
) {
    val selected = remember(items) { mutableStateListOf<Long>() }
    var query by remember { mutableStateOf("") }
    var filter by remember { mutableStateOf("All") }
    var focused by remember { mutableStateOf<EvidenceEntity?>(null) }
    val filtered = items.filter { row ->
        val matchFilter = when (filter) {
            "Open" -> row.security.contains("OPEN", ignoreCase = true)
            "Hidden" -> row.ssid.equals("<hidden>", ignoreCase = true)
            "Strong" -> (row.rssi ?: -999) >= -60
            else -> true
        }
        val q = query.trim().lowercase(Locale.US)
        val matchQuery = q.isBlank() ||
            row.ssid.lowercase(Locale.US).contains(q) ||
            row.bssid.lowercase(Locale.US).contains(q) ||
            row.security.lowercase(Locale.US).contains(q)
        matchFilter && matchQuery
    }
    LazyColumn(modifier = modifier.fillMaxSize().padding(12.dp)) {
        item {
            Row(
                modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Button(
                    onClick = { selected.addAll(filtered.map { it.id }) },
                    enabled = filtered.isNotEmpty()
                ) { Text("Select All") }
                Button(
                    onClick = { onDeleteSelected(selected.toSet()); selected.clear() },
                    enabled = selected.isNotEmpty()
                ) { Text("Delete Selected (${selected.size})") }
            }
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                label = { Text("Search SSID / BSSID / Security") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip("All", filter) { filter = it }
                FilterChip("Open", filter) { filter = it }
                FilterChip("Hidden", filter) { filter = it }
                FilterChip("Strong", filter) { filter = it }
            }
            Spacer(Modifier.height(6.dp))
            Text("Showing ${filtered.size} / ${items.size}", style = MaterialTheme.typography.bodySmall)
        }
        items(filtered, key = { it.id }) { row ->
            Card(Modifier.padding(vertical = 4.dp)) {
                Row(Modifier.fillMaxWidth().padding(12.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Checkbox(
                        checked = selected.contains(row.id),
                        onCheckedChange = { checked ->
                            if (checked) selected.add(row.id) else selected.remove(row.id)
                        }
                    )
                    Column {
                        Text(row.ssid, style = MaterialTheme.typography.titleMedium)
                        Text("${row.bssid}  ch=${row.channel ?: "?"} rssi=${row.rssi ?: 0}")
                        Text("${row.security}  lat=${row.latitude ?: 0.0}, lon=${row.longitude ?: 0.0}")
                        Button(
                            onClick = { focused = row },
                            modifier = Modifier.padding(top = 6.dp)
                        ) { Text("Inspect") }
                    }
                }
            }
        }
    }

    if (focused != null) {
        val row = focused!!
        androidx.compose.material3.AlertDialog(
            onDismissRequest = { focused = null },
            confirmButton = {
                Button(onClick = { focused = null }) { Text("Close") }
            },
            title = { Text("Evidence Detail") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("SSID: ${row.ssid}")
                    Text("BSSID: ${row.bssid}")
                    Text("Security: ${row.security}")
                    Text("Channel: ${row.channel ?: "?"}   RSSI: ${row.rssi ?: 0}")
                    Text("GPS: ${row.latitude ?: 0.0}, ${row.longitude ?: 0.0}")
                    Text("Source: ${row.sourceName}")
                }
            }
        )
    }
}

@Composable
private fun FilterChip(label: String, active: String, onClick: (String) -> Unit) {
    Button(onClick = { onClick(label) }) {
        Text(if (label == active) "[$label]" else label)
    }
}
