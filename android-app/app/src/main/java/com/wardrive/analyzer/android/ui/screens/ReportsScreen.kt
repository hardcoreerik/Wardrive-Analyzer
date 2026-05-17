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
import com.wardrive.analyzer.android.data.model.ReportEntity

@Composable
fun ReportsScreen(modifier: Modifier = Modifier, reports: List<ReportEntity>) {
    LazyColumn(modifier = modifier.fillMaxSize().padding(12.dp)) {
        items(reports, key = { it.id }) { report ->
            Card(Modifier.padding(vertical = 4.dp)) {
                Column(Modifier.padding(12.dp)) {
                    Text(report.title, style = MaterialTheme.typography.titleMedium)
                    Text(report.reportType)
                    Text(report.body)
                }
            }
        }
    }
}
