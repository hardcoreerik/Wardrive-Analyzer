package com.wardrive.analyzer.android.ui.screens

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.wardrive.analyzer.android.data.model.RunEntity
import java.text.DateFormat
import java.util.Date

@Composable
fun RunsScreen(
    modifier: Modifier = Modifier,
    runs: List<RunEntity>,
    onDeleteSelected: (Set<Long>) -> Unit
) {
    val selected = remember(runs) { mutableStateListOf<Long>() }
    LazyColumn(modifier = modifier.fillMaxSize().padding(12.dp)) {
        item {
            Row(
                modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Button(
                    onClick = { selected.addAll(runs.map { it.id }) },
                    enabled = runs.isNotEmpty()
                ) { Text("Select All") }
                Button(
                    onClick = { onDeleteSelected(selected.toSet()); selected.clear() },
                    enabled = selected.isNotEmpty()
                ) { Text("Delete Selected (${selected.size})") }
            }
        }
        items(runs, key = { it.id }) { run ->
            Card(Modifier.padding(vertical = 4.dp)) {
                Row(Modifier.fillMaxWidth().padding(12.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Checkbox(
                        checked = selected.contains(run.id),
                        onCheckedChange = { checked ->
                            if (checked) selected.add(run.id) else selected.remove(run.id)
                        }
                    )
                    Column {
                        Text(run.name, style = MaterialTheme.typography.titleMedium)
                        Text("Evidence ${run.evidenceCount} | Open ${run.openNetworkCount} | Hidden ${run.hiddenSsidCount}")
                        if (run.pcapPacketCount > 0 || run.pcapBytes > 0) {
                            Text("PCAP packets ${run.pcapPacketCount} | EAPOL ${run.pcapEapolCount} | AP ${run.pcapApCount} | STA ${run.pcapStationCount}")
                            Text("Handshake ${run.handshakeConfidence}")
                        }
                        Text("Risk ${run.riskScore}/100")
                        Text(DateFormat.getDateTimeInstance().format(Date(run.createdAt)))
                    }
                }
            }
        }
    }
}
