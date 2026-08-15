package com.wardrive.analyzer.android.ui.screens

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import com.wardrive.analyzer.android.data.model.ReportEntity
import java.util.Locale

@Composable
fun ReportsScreen(
    modifier: Modifier = Modifier,
    reports: List<ReportEntity>,
    onJumpToEvidence: () -> Unit = {}
) {
    var query by remember { mutableStateOf("") }
    var typeFilter by remember { mutableStateOf("All") }
    val expanded = remember { mutableStateMapOf<Long, Boolean>() }
    val pinned = remember { mutableStateMapOf<Long, Boolean>() }
    val notes = remember { mutableStateMapOf<Long, String>() }
    val filtered = reports.filter { r ->
        val byType = typeFilter == "All" || r.reportType.equals(typeFilter, ignoreCase = true)
        val q = query.trim().lowercase(Locale.US)
        val byQuery = q.isBlank() ||
            r.title.lowercase(Locale.US).contains(q) ||
            r.body.lowercase(Locale.US).contains(q) ||
            r.reportType.lowercase(Locale.US).contains(q)
        byType && byQuery
    }
    LazyColumn(modifier = modifier.fillMaxSize().padding(12.dp)) {
        item {
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                label = { Text("Search reports") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = { typeFilter = "All" }) { Text(if (typeFilter == "All") "[All]" else "All") }
                Button(onClick = { typeFilter = "summary" }) { Text(if (typeFilter == "summary") "[Summary]" else "Summary") }
                Button(onClick = { typeFilter = "pcap_summary" }) { Text(if (typeFilter == "pcap_summary") "[PCAP]" else "PCAP") }
            }
            Spacer(Modifier.height(6.dp))
            Text("Showing ${filtered.size} / ${reports.size}", style = MaterialTheme.typography.bodySmall)
        }
        items(filtered, key = { it.id }) { report ->
            val isExpanded = expanded[report.id] == true
            val riskColor = when {
                report.body.contains("Risk score: 8", ignoreCase = true) ||
                    report.body.contains("Risk score: 9", ignoreCase = true) -> Color(0xFFFF4D6D)
                report.body.contains("Risk score: 6", ignoreCase = true) ||
                    report.body.contains("Risk score: 7", ignoreCase = true) -> Color(0xFFFFB703)
                else -> MaterialTheme.colorScheme.secondary
            }
            Card(Modifier.padding(vertical = 4.dp)) {
                Column(Modifier.padding(12.dp)) {
                    Text(report.title, style = MaterialTheme.typography.titleMedium, color = riskColor)
                    Text(report.reportType, color = MaterialTheme.colorScheme.secondary)
                    Text(
                        if (isExpanded || report.body.length < 220) report.body else report.body.take(220) + " ...",
                        modifier = Modifier.padding(top = 4.dp)
                    )
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Button(onClick = { expanded[report.id] = !isExpanded }) {
                            Text(if (isExpanded) "Collapse" else "Expand")
                        }
                        Button(onClick = { pinned[report.id] = !(pinned[report.id] ?: false) }) {
                            Text(if (pinned[report.id] == true) "Pinned" else "Pin")
                        }
                        Button(onClick = onJumpToEvidence) {
                            Text("Jump to Evidence")
                        }
                    }
                    OutlinedTextField(
                        value = notes[report.id] ?: "",
                        onValueChange = { notes[report.id] = it },
                        label = { Text("Analyst Note") },
                        modifier = Modifier.fillMaxWidth().padding(top = 8.dp)
                    )
                }
            }
        }
    }
}
