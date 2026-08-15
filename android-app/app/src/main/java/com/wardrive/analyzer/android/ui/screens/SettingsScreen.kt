package com.wardrive.analyzer.android.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.wardrive.analyzer.android.data.model.ProjectProfileEntity
import com.wardrive.analyzer.android.data.model.SyncRecordEntity

@Composable
fun SettingsScreen(
    modifier: Modifier = Modifier,
    dropboxToken: String,
    dropboxFolder: String,
    dropboxZipName: String,
    dropboxStatus: String,
    projectProfiles: List<ProjectProfileEntity>,
    activeProjectSlug: String,
    syncRecords: List<SyncRecordEntity>,
    isSyncingDropbox: Boolean,
    onDropboxTokenChange: (String) -> Unit,
    onDropboxFolderChange: (String) -> Unit,
    onDropboxZipNameChange: (String) -> Unit,
    onSaveDropboxConfig: () -> Unit,
    onSyncFromDropbox: () -> Unit,
    onRefreshProjects: () -> Unit,
    onSetActiveProject: (String) -> Unit
) {
    Column(
        modifier = modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Text("Settings + Sync", style = MaterialTheme.typography.headlineMedium)
        Card {
            Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = dropboxToken,
                    onValueChange = onDropboxTokenChange,
                    label = { Text("Dropbox Access Token") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = dropboxFolder,
                    onValueChange = onDropboxFolderChange,
                    label = { Text("Dropbox Projects Root") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = dropboxZipName,
                    onValueChange = onDropboxZipNameChange,
                    label = { Text("Project Zip Filename") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Button(onClick = onSaveDropboxConfig, modifier = Modifier.fillMaxWidth()) { Text("Save Config") }
                Button(onClick = onRefreshProjects, modifier = Modifier.fillMaxWidth()) { Text("Refresh Projects") }
                Button(onClick = onSyncFromDropbox, modifier = Modifier.fillMaxWidth(), enabled = !isSyncingDropbox) {
                    Text(if (isSyncingDropbox) "Syncing..." else "Sync from Dropbox")
                }
                if (isSyncingDropbox) LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                Text(dropboxStatus, style = MaterialTheme.typography.bodySmall)
            }
        }

        Card {
            Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Active Project: ${if (activeProjectSlug.isBlank()) "none" else activeProjectSlug}")
                projectProfiles.forEach { p ->
                    Button(onClick = { onSetActiveProject(p.slug) }, modifier = Modifier.fillMaxWidth()) {
                        Text(if (p.slug == activeProjectSlug) "[ACTIVE] ${p.displayName}" else p.displayName)
                    }
                }
                if (syncRecords.isNotEmpty()) {
                    Text("Recent Sync Events", style = MaterialTheme.typography.titleMedium)
                    syncRecords.take(6).forEach { row ->
                        Text("${row.direction} ${row.projectSlug}: ${row.status} - ${row.path}", style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
    }
}
