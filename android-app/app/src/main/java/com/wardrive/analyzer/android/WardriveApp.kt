package com.wardrive.analyzer.android

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Dashboard
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Map
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.withFrameMillis
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.wardrive.analyzer.android.data.model.ProjectProfileEntity
import com.wardrive.analyzer.android.marauder.MarauderConnectionStatus
import com.wardrive.analyzer.android.ui.screens.DashboardScreen
import com.wardrive.analyzer.android.ui.screens.EvidenceScreen
import com.wardrive.analyzer.android.ui.screens.MarauderImportsScreen
import com.wardrive.analyzer.android.ui.screens.MarauderLiveScreen
import com.wardrive.analyzer.android.ui.screens.PixelMapScreen
import com.wardrive.analyzer.android.ui.screens.ReportsScreen
import com.wardrive.analyzer.android.ui.screens.RunsScreen
import com.wardrive.analyzer.android.ui.screens.SettingsScreen

enum class Tab(val label: String) {
    Home("Home"),
    Live("Live"),
    Map("Map"),
    Files("Files"),
    Settings("Settings")
}

private enum class ProjectTargetAction {
    SAVE_SESSION_LOG,
    SHARE_DIAGNOSTICS,
    EXPORT_AP_CSV,
    IMPORT_FILES,
    IMPORT_FOLDER,
    EXPORT_WARDRIVE_CSV,
    EXPORT_WARDRIVE_JSON
}

@Composable
fun WardriveApp(viewModel: WardriveViewModel) {
    var selected by remember { mutableStateOf(Tab.Home) }
    var filesSection by remember { mutableStateOf("imports") }
    val evidence by viewModel.evidence.collectAsStateWithLifecycle(initialValue = emptyList())
    val runs by viewModel.runs.collectAsStateWithLifecycle(initialValue = emptyList())
    val reports by viewModel.reports.collectAsStateWithLifecycle(initialValue = emptyList())
    val marauderConnection by viewModel.marauderConnection.collectAsStateWithLifecycle()
    val marauderTerminal by viewModel.marauderTerminal.collectAsStateWithLifecycle()
    val marauderDiagnostics by viewModel.marauderDiagnostics.collectAsStateWithLifecycle()
    val marauderImportedFiles by viewModel.marauderImportedFiles.collectAsStateWithLifecycle(initialValue = emptyList())
    val marauderApRecords by viewModel.marauderApRecords.collectAsStateWithLifecycle(initialValue = emptyList())
    val marauderWardriveRecords by viewModel.marauderWardriveRecords.collectAsStateWithLifecycle(initialValue = emptyList())
    val projectProfiles by viewModel.projectProfiles.collectAsStateWithLifecycle(initialValue = emptyList())
    val syncRecords by viewModel.syncRecords.collectAsStateWithLifecycle(initialValue = emptyList())
    val activeProjectSlug by viewModel.activeProjectSlug.collectAsStateWithLifecycle()
    val lastCommand by viewModel.lastCommand.collectAsStateWithLifecycle()
    val mascotMessage by viewModel.mascotMessage.collectAsStateWithLifecycle()
    val mascotState by viewModel.mascotState.collectAsStateWithLifecycle()
    val marauderImportStatus by viewModel.marauderImportStatus.collectAsStateWithLifecycle()
    val evidenceCount by viewModel.evidenceCount.collectAsStateWithLifecycle(initialValue = 0)
    val openCount by viewModel.openCount.collectAsStateWithLifecycle(initialValue = 0)
    val dropboxStatus by viewModel.dropboxStatus.collectAsStateWithLifecycle()
    val isSyncingDropbox by viewModel.isSyncingDropbox.collectAsStateWithLifecycle()
    val isRefreshingProjects by viewModel.isRefreshingProjects.collectAsStateWithLifecycle()
    val mapState by viewModel.mapScreenState.collectAsStateWithLifecycle()
    var dropboxToken by remember { mutableStateOf(viewModel.getDropboxToken()) }
    var dropboxFolder by remember { mutableStateOf(viewModel.getDropboxFolder()) }
    var dropboxZipName by remember { mutableStateOf(viewModel.getDropboxZipName()) }
    var pendingProjectAction by remember { mutableStateOf<ProjectTargetAction?>(null) }
    var pendingImportProjectSlug by remember { mutableStateOf<String?>(null) }

    val marauderFileLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        if (uris.isNotEmpty()) viewModel.importMarauderUris(uris, pendingImportProjectSlug)
        pendingImportProjectSlug = null
    }
    val marauderFolderLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri: Uri? ->
        if (uri != null) viewModel.importMarauderTree(uri, pendingImportProjectSlug)
        pendingImportProjectSlug = null
    }

    LaunchedEffect(Unit) {
        if (dropboxToken.isNotBlank()) {
            viewModel.refreshDropboxProjects()
        }
    }

    val totalPcapPackets = runs.sumOf { it.pcapPacketCount }
    val highRiskRuns = runs.count { it.riskScore >= 60 }
    val executeProjectAction: (ProjectTargetAction, String?) -> Unit = { action, slug ->
        when (action) {
            ProjectTargetAction.SAVE_SESSION_LOG -> viewModel.saveCurrentMarauderSessionLog(slug)
            ProjectTargetAction.SHARE_DIAGNOSTICS -> viewModel.shareMarauderDiagnosticsLog(slug)
            ProjectTargetAction.EXPORT_AP_CSV -> viewModel.exportMarauderApCsv(slug)
            ProjectTargetAction.IMPORT_FILES -> {
                pendingImportProjectSlug = slug
                marauderFileLauncher.launch(
                    arrayOf(
                        "application/vnd.tcpdump.pcap",
                        "application/octet-stream",
                        "text/plain",
                        "text/csv"
                    )
                )
            }
            ProjectTargetAction.IMPORT_FOLDER -> {
                pendingImportProjectSlug = slug
                marauderFolderLauncher.launch(null)
            }
            ProjectTargetAction.EXPORT_WARDRIVE_CSV -> viewModel.exportMarauderWardriveCsv(slug)
            ProjectTargetAction.EXPORT_WARDRIVE_JSON -> viewModel.exportMarauderWardriveJson(slug)
        }
    }

    Box(modifier = Modifier.fillMaxSize()) {
        CyberBackdrop()
        Scaffold(
            containerColor = Color.Transparent,
            bottomBar = {
                NavigationBar(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.95f)
                ) {
                    Tab.entries.forEach { tab ->
                        NavigationBarItem(
                            selected = tab == selected,
                            onClick = { selected = tab },
                            label = { Text(tab.label) },
                            icon = {
                                Icon(
                                    imageVector = when (tab) {
                                        Tab.Home -> Icons.Default.Dashboard
                                        Tab.Live -> Icons.Default.Terminal
                                        Tab.Map -> Icons.Default.Map
                                        Tab.Files -> Icons.Default.FolderOpen
                                        Tab.Settings -> Icons.Default.Settings
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
                Tab.Home -> DashboardScreen(
                    modifier = Modifier.padding(padding),
                    evidenceCount = evidenceCount,
                    openCount = openCount,
                    runCount = runs.size,
                    reportCount = reports.size,
                    totalPcapPackets = totalPcapPackets,
                    highRiskRuns = highRiskRuns,
                    lastImport = runs.firstOrNull()?.name ?: "No imports yet",
                    dropboxStatus = dropboxStatus,
                    projectProfiles = projectProfiles,
                    activeProjectSlug = activeProjectSlug,
                    marauderConnected = marauderConnection.status == MarauderConnectionStatus.CONNECTED,
                    syncRecords = syncRecords,
                    isSyncingDropbox = isSyncingDropbox,
                    isRefreshingProjects = isRefreshingProjects,
                    onRefreshProjects = { viewModel.refreshDropboxProjects() },
                    onSetActiveProject = { viewModel.setActiveProject(it) },
                    onOpenLiveTab = { selected = Tab.Live }
                )

                Tab.Live -> MarauderLiveScreen(
                    modifier = Modifier.padding(padding),
                    state = marauderConnection,
                    terminalLines = marauderTerminal,
                    apRecords = marauderApRecords,
                    diagnostics = marauderDiagnostics,
                    lastCommand = lastCommand,
                    mascotMessage = mascotMessage,
                    mascotState = mascotState,
                    onRefresh = { viewModel.refreshMarauderDevice() },
                    onConnect = { viewModel.connectMarauder() },
                    onDisconnect = { viewModel.disconnectMarauder() },
                    onSendCommand = { viewModel.sendMarauderCommand(it) },
                    onSaveLog = { pendingProjectAction = ProjectTargetAction.SAVE_SESSION_LOG },
                    onShareDiagnostics = { pendingProjectAction = ProjectTargetAction.SHARE_DIAGNOSTICS },
                    onExportApCsv = { pendingProjectAction = ProjectTargetAction.EXPORT_AP_CSV }
                )

                Tab.Map -> PixelMapScreen(
                    modifier = Modifier.padding(padding),
                    state = mapState,
                    onFilterChanged = { viewModel.setMapFilter(it) },
                    onSelectEntity = { viewModel.selectMapEntity(it) },
                    onViewportChanged = { dx, dy -> viewModel.setMapViewportDelta(dx, dy) },
                    onViewportScale = { zoomDelta -> viewModel.scaleMapViewport(zoomDelta) }
                )

                Tab.Files -> Column(modifier = Modifier.padding(padding).fillMaxSize()) {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 10.dp, vertical = 6.dp),
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        TextButton(onClick = { filesSection = "imports" }) { Text(if (filesSection == "imports") "[Imports]" else "Imports") }
                        TextButton(onClick = { filesSection = "evidence" }) { Text(if (filesSection == "evidence") "[Evidence]" else "Evidence") }
                        TextButton(onClick = { filesSection = "runs" }) { Text(if (filesSection == "runs") "[Runs]" else "Runs") }
                        TextButton(onClick = { filesSection = "reports" }) { Text(if (filesSection == "reports") "[Reports]" else "Reports") }
                    }
                    when (filesSection) {
                        "evidence" -> EvidenceScreen(items = evidence, onDeleteSelected = { ids -> viewModel.deleteEvidence(ids) })
                        "runs" -> RunsScreen(runs = runs, onDeleteSelected = { ids -> viewModel.deleteRuns(ids) })
                        "reports" -> ReportsScreen(reports = reports, onJumpToEvidence = { filesSection = "evidence" })
                        else -> MarauderImportsScreen(
                            imports = marauderImportedFiles,
                            wardriveRecords = marauderWardriveRecords,
                            status = marauderImportStatus,
                            onPickFiles = { pendingProjectAction = ProjectTargetAction.IMPORT_FILES },
                            onPickFolder = { pendingProjectAction = ProjectTargetAction.IMPORT_FOLDER },
                            onExportCsv = { pendingProjectAction = ProjectTargetAction.EXPORT_WARDRIVE_CSV },
                            onExportJson = { pendingProjectAction = ProjectTargetAction.EXPORT_WARDRIVE_JSON },
                            onShareFile = { viewModel.shareImportedMarauderFile(it) }
                        )
                    }
                }

                Tab.Settings -> SettingsScreen(
                    modifier = Modifier.padding(padding),
                    dropboxToken = dropboxToken,
                    dropboxFolder = dropboxFolder,
                    dropboxZipName = dropboxZipName,
                    dropboxStatus = dropboxStatus,
                    projectProfiles = projectProfiles,
                    activeProjectSlug = activeProjectSlug,
                    syncRecords = syncRecords,
                    isSyncingDropbox = isSyncingDropbox,
                    onDropboxTokenChange = { dropboxToken = it },
                    onDropboxFolderChange = { dropboxFolder = it },
                    onDropboxZipNameChange = { dropboxZipName = it },
                    onSaveDropboxConfig = { viewModel.saveDropboxConfig(dropboxToken, dropboxFolder, dropboxZipName) },
                    onSyncFromDropbox = { viewModel.syncFromDropbox() },
                    onRefreshProjects = { viewModel.refreshDropboxProjects() },
                    onSetActiveProject = { viewModel.setActiveProject(it) }
                )
            }
        }

        pendingProjectAction?.let { action ->
            ProjectTargetSheet(
                projects = projectProfiles,
                activeProjectSlug = activeProjectSlug,
                onDismiss = { pendingProjectAction = null },
                onConfirm = { existingSlug, newProjectName ->
                    val finalSlug = when {
                        !newProjectName.isNullOrBlank() -> viewModel.activateOrCreateProject(newProjectName)
                        !existingSlug.isNullOrBlank() -> {
                            viewModel.setActiveProject(existingSlug)
                            existingSlug
                        }
                        else -> activeProjectSlug.ifBlank { null }
                    }
                    executeProjectAction(action, finalSlug)
                    pendingProjectAction = null
                }
            )
        }
    }
}

@Composable
private fun ProjectTargetSheet(
    projects: List<ProjectProfileEntity>,
    activeProjectSlug: String,
    onDismiss: () -> Unit,
    onConfirm: (existingSlug: String?, newProjectName: String?) -> Unit
) {
    var selectedSlug by remember(projects, activeProjectSlug) {
        mutableStateOf(
            activeProjectSlug.ifBlank { projects.firstOrNull()?.slug.orEmpty() }
        )
    }
    var newProjectName by remember { mutableStateOf("") }
    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(Color(0xCC05070D))
                .padding(12.dp)
        ) {
            Card(modifier = Modifier.fillMaxSize()) {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(12.dp)
                ) {
                    Text("Project Target", style = MaterialTheme.typography.headlineMedium, color = MaterialTheme.colorScheme.primary)
                    Spacer(Modifier.height(6.dp))
                    Text("Choose an existing project or create a new one. Marauder will route this action into that project tree.")
                    Spacer(Modifier.height(10.dp))
                    Column(
                        modifier = Modifier
                            .weight(1f)
                            .fillMaxWidth()
                            .verticalScroll(rememberScrollState()),
                        verticalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        if (projects.isEmpty()) {
                            Text("No discovered projects yet. Create one below.")
                        }
                        projects.forEach { profile ->
                            Button(
                                onClick = { selectedSlug = profile.slug },
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                val active = if (profile.slug == selectedSlug) "[SELECTED] " else ""
                                Text("$active${profile.displayName}")
                            }
                        }
                    }
                    OutlinedTextField(
                        value = newProjectName,
                        onValueChange = { newProjectName = it },
                        label = { Text("Create new project") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                    Spacer(Modifier.height(10.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                        TextButton(onClick = onDismiss, modifier = Modifier.weight(1f)) { Text("Cancel") }
                        TextButton(
                            onClick = {
                                onConfirm(
                                    selectedSlug.ifBlank { null },
                                    newProjectName.trim().ifBlank { null }
                                )
                            },
                            modifier = Modifier.weight(1f)
                        ) { Text("Continue") }
                    }
                }
            }
        }
    }
}

@Composable
private fun CyberBackdrop() {
    var tick by remember { mutableStateOf(0L) }
    LaunchedEffect(Unit) {
        while (true) tick = withFrameMillis { it }
    }
    val phase = (tick % 8000L).toFloat() / 8000f
    val shift = phase * 1200f
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.verticalGradient(
                    colors = listOf(Color(0xFF090312), Color(0xFF12051E), Color(0xFF070B14))
                )
            )
    ) {
        Canvas(modifier = Modifier.fillMaxSize()) {
            val spacing = 48f
            var y = -spacing + (shift % spacing)
            while (y < size.height + spacing) {
                drawLine(
                    color = Color(0x2200F5D4),
                    start = Offset(0f, y),
                    end = Offset(size.width, y),
                    strokeWidth = 1f
                )
                y += spacing
            }
        }
    }
}
