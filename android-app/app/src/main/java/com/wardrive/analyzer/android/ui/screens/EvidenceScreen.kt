package com.wardrive.analyzer.android.ui.screens

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.wardrive.analyzer.android.data.model.EvidenceEntity

@Composable
fun EvidenceScreen(modifier: Modifier = Modifier, items: List<EvidenceEntity>) {
    LazyColumn(modifier = modifier.fillMaxSize().padding(12.dp)) {
        items(items, key = { it.id }) { row ->
            Card(Modifier.padding(vertical = 4.dp)) {
                Column(Modifier.padding(12.dp)) {
                    Text(row.ssid, style = MaterialTheme.typography.titleMedium)
                    Text("${row.bssid}  ch=${row.channel ?: "?"} rssi=${row.rssi ?: 0}")
                    Text("${row.security}  lat=${row.latitude ?: 0.0}, lon=${row.longitude ?: 0.0}")
                }
            }
        }
    }
}
