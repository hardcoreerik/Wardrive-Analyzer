package com.wardrive.analyzer.android

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Assessment
import androidx.compose.material.icons.filled.CloudUpload
import androidx.compose.material.icons.filled.Dashboard
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Timeline
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.wardrive.analyzer.android.ui.screens.DashboardScreen
import com.wardrive.analyzer.android.ui.screens.EvidenceScreen
import com.wardrive.analyzer.android.ui.screens.ReportsScreen
import com.wardrive.analyzer.android.ui.screens.RunsScreen
import kotlinx.coroutines.launch

enum class Tab(val label: String) {
    Dashboard("Dashboard"),
    Evidence("Evidence"),
    Runs("Runs"),
    Reports("Reports"),
    Import("Import")
}

@Composable
fun WardriveApp(viewModel: WardriveViewModel) {
    var selected by remember { mutableStateOf(Tab.Dashboard) }
    val scope = rememberCoroutineScope()
    val evidence by viewModel.evidence.collectAsStateWithLifecycle(initialValue = emptyList())
    val runs by viewModel.runs.collectAsStateWithLifecycle(initialValue = emptyList())
    val reports by viewModel.reports.collectAsStateWithLifecycle(initialValue = emptyList())
    val evidenceCount by viewModel.evidenceCount.collectAsStateWithLifecycle(initialValue = 0)
    val openCount by viewModel.openCount.collectAsStateWithLifecycle(initialValue = 0)

    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri: Uri? ->
        if (uri != null) {
            scope.launch { viewModel.importUri(uri) }
        }
    }

    LaunchedEffect(selected) {
        if (selected == Tab.Import) {
            launcher.launch("*/*")
            selected = Tab.Dashboard
        }
    }

    Scaffold(
        bottomBar = {
            NavigationBar {
                Tab.entries.forEach { tab ->
                    NavigationBarItem(
                        selected = tab == selected,
                        onClick = { selected = tab },
                        label = { Text(tab.label) },
                        icon = {
                            Icon(
                                imageVector = when (tab) {
                                    Tab.Dashboard -> Icons.Default.Dashboard
                                    Tab.Evidence -> Icons.Default.Assessment
                                    Tab.Runs -> Icons.Default.Timeline
                                    Tab.Reports -> Icons.Default.Description
                                    Tab.Import -> Icons.Default.CloudUpload
                                },
                                contentDescription = tab.label
                            )
                        }
                    )
                }
            }
        }
    ) { padding ->
        when (selected) {
            Tab.Dashboard -> DashboardScreen(
                modifier = Modifier.padding(padding),
                evidenceCount = evidenceCount,
                openCount = openCount,
                runCount = runs.size,
                reportCount = reports.size,
                lastImport = runs.firstOrNull()?.name ?: "No imports yet"
            )
            Tab.Evidence -> EvidenceScreen(Modifier.padding(padding), evidence)
            Tab.Runs -> RunsScreen(Modifier.padding(padding), runs)
            Tab.Reports -> ReportsScreen(Modifier.padding(padding), reports)
            Tab.Import -> Text("Pick a file to import", modifier = Modifier.padding(padding))
        }
    }
}
