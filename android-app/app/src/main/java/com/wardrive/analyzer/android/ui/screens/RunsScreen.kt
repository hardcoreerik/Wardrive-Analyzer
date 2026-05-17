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
import com.wardrive.analyzer.android.data.model.RunEntity
import java.text.DateFormat
import java.util.Date

@Composable
fun RunsScreen(modifier: Modifier = Modifier, runs: List<RunEntity>) {
    LazyColumn(modifier = modifier.fillMaxSize().padding(12.dp)) {
        items(runs, key = { it.id }) { run ->
            Card(Modifier.padding(vertical = 4.dp)) {
                Column(Modifier.padding(12.dp)) {
                    Text(run.name, style = MaterialTheme.typography.titleMedium)
                    Text("Evidence ${run.evidenceCount} | Open ${run.openNetworkCount} | Hidden ${run.hiddenSsidCount}")
                    Text(DateFormat.getDateTimeInstance().format(Date(run.createdAt)))
                }
            }
        }
    }
}
