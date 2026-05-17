package com.wardrive.analyzer.android.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@Composable
fun DashboardScreen(
    modifier: Modifier = Modifier,
    evidenceCount: Int,
    openCount: Int,
    runCount: Int,
    reportCount: Int,
    lastImport: String
) {
    Column(
        modifier = modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Text("Mission Control", style = MaterialTheme.typography.headlineMedium)
        MetricCard("Evidence Rows", evidenceCount.toString())
        MetricCard("Open Networks", openCount.toString())
        MetricCard("Runs", runCount.toString())
        MetricCard("Reports", reportCount.toString())
        MetricCard("Last Import", lastImport)
    }
}

@Composable
private fun MetricCard(title: String, value: String) {
    Card {
        Column(Modifier.padding(16.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium)
            Text(value, style = MaterialTheme.typography.bodyLarge)
        }
    }
}
