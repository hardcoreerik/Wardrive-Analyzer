package com.wardrive.analyzer.android

import android.content.Intent
import android.net.Uri
import android.provider.OpenableColumns
import android.util.Log
import androidx.core.content.FileProvider
import androidx.documentfile.provider.DocumentFile
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.wardrive.analyzer.android.data.model.MarauderApRecordEntity
import com.wardrive.analyzer.android.data.model.EvidenceEntity
import com.wardrive.analyzer.android.data.model.MarauderImportedFileEntity
import com.wardrive.analyzer.android.data.model.ProjectProfileEntity
import com.wardrive.analyzer.android.data.model.SyncRecordEntity
import com.wardrive.analyzer.android.data.model.MarauderWardriveRecordEntity
import com.wardrive.analyzer.android.data.model.ReportEntity
import com.wardrive.analyzer.android.data.model.RunEntity
import com.wardrive.analyzer.android.data.repo.WardriveRepository
import com.wardrive.analyzer.android.marauder.MarauderConnectionStatus
import com.wardrive.analyzer.android.marauder.MarauderDeviceInfo
import com.wardrive.analyzer.android.marauder.MarauderFileClassifier
import com.wardrive.analyzer.android.marauder.MarauderImportFileType
import com.wardrive.analyzer.android.marauder.MarauderMascotState
import com.wardrive.analyzer.android.marauder.MarauderOutputParser
import com.wardrive.analyzer.android.marauder.MarauderWardriveCsvParser
import com.wardrive.analyzer.android.marauder.Sha256
import com.wardrive.analyzer.android.sync.ProjectProfile
import com.wardrive.analyzer.android.sync.SyncRecord
import com.wardrive.analyzer.android.sync.DropboxSyncService
import com.wardrive.analyzer.android.ui.map.MapAggregation
import com.wardrive.analyzer.android.ui.map.MapEntityTypeFilter
import com.wardrive.analyzer.android.ui.map.MapScreenState
import com.wardrive.analyzer.android.ui.map.MapViewport
import com.wardrive.analyzer.android.usb.MarauderUsbSerialManager
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import kotlinx.coroutines.launch
import java.io.File
import java.io.BufferedReader
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStreamReader
import java.util.Locale
import java.util.UUID
import java.util.zip.ZipInputStream
import kotlin.math.roundToInt

class WardriveViewModel(
    private val app: WardriveApplication
) : ViewModel() {
    private val tag = "WardriveViewModel"
    private val repo: WardriveRepository = app.repository
    private val prefs = app.getSharedPreferences("dropbox_sync", 0)
    private val dropboxService = DropboxSyncService()
    private val marauderParser = MarauderOutputParser()
    private val marauderCsvParser = MarauderWardriveCsvParser()
    private val serialCarry = StringBuilder()
    private val marauderLogLock = Any()
    private val terminalUiLock = Any()
    private val terminalUiBuffer = mutableListOf<String>()
    private var terminalFlushJob: Job? = null
    private var currentMarauderSessionId: String? = null
    private var currentMarauderRawLogFile: File? = null
    private var lastTerminalBaseLine: String? = null
    private var lastTerminalRepeatCount: Int = 0

    val evidence: Flow<List<EvidenceEntity>> = repo.evidence
    val runs: Flow<List<RunEntity>> = repo.runs
    val reports: Flow<List<ReportEntity>> = repo.reports
    val marauderImportedFiles: Flow<List<MarauderImportedFileEntity>> = repo.marauderImportedFiles
    val marauderApRecords: Flow<List<MarauderApRecordEntity>> = repo.marauderApRecords
    val marauderWardriveRecords: Flow<List<MarauderWardriveRecordEntity>> = repo.marauderWardriveRecords
    val projectProfiles: Flow<List<ProjectProfileEntity>> = repo.projectProfiles
    val syncRecords: Flow<List<SyncRecordEntity>> = repo.syncRecords
    val evidenceCount = repo.evidenceCount
    val openCount = repo.openCount
    private val _dropboxStatus = MutableStateFlow("Dropbox not synced yet.")
    val dropboxStatus: StateFlow<String> = _dropboxStatus.asStateFlow()
    private val _isSyncingDropbox = MutableStateFlow(false)
    val isSyncingDropbox: StateFlow<Boolean> = _isSyncingDropbox.asStateFlow()
    private val _isRefreshingProjects = MutableStateFlow(false)
    val isRefreshingProjects: StateFlow<Boolean> = _isRefreshingProjects.asStateFlow()
    private val _syncCompletedSignal = MutableStateFlow(0L)
    val syncCompletedSignal: StateFlow<Long> = _syncCompletedSignal.asStateFlow()
    private val _marauderTerminal = MutableStateFlow<List<String>>(emptyList())
    val marauderTerminal: StateFlow<List<String>> = _marauderTerminal.asStateFlow()
    private val _marauderDiagnostics = MutableStateFlow<List<String>>(listOf("Marauder diagnostics ready."))
    val marauderDiagnostics: StateFlow<List<String>> = _marauderDiagnostics.asStateFlow()
    private val _marauderImportStatus = MutableStateFlow("No Marauder files imported yet.")
    val marauderImportStatus: StateFlow<String> = _marauderImportStatus.asStateFlow()
    private val _activeProjectSlug = MutableStateFlow("")
    val activeProjectSlug: StateFlow<String> = _activeProjectSlug.asStateFlow()
    private val _lastCommand = MutableStateFlow("")
    val lastCommand: StateFlow<String> = _lastCommand.asStateFlow()
    private val _mascotMessage = MutableStateFlow("Marauder: Link up and run recon.")
    val mascotMessage: StateFlow<String> = _mascotMessage.asStateFlow()
    private val _mascotState = MutableStateFlow(MarauderMascotState.WARNING)
    val mascotState: StateFlow<MarauderMascotState> = _mascotState.asStateFlow()
    private val _mapFilter = MutableStateFlow(MapEntityTypeFilter.ALL)
    val mapFilter: StateFlow<MapEntityTypeFilter> = _mapFilter.asStateFlow()
    private val _selectedMapEntityId = MutableStateFlow<String?>(null)
    private val _mapViewport = MutableStateFlow(MapViewport())
    private val mapBaseData = combine(
        evidence,
        marauderWardriveRecords,
        reports,
        runs
    ) { evidenceRows, wardriveRows, reportRows, runRows ->
        Quadruple(evidenceRows, wardriveRows, reportRows, runRows.size)
    }
    val mapScreenState: StateFlow<MapScreenState> = combine(
        mapBaseData,
        _mapFilter,
        _selectedMapEntityId,
        _mapViewport
    ) { base, filter, selectedId, viewport ->
        MapAggregation.buildState(
            evidence = base.first,
            wardrive = base.second,
            reports = base.third,
            runsCount = base.fourth,
            filter = filter,
            selectedEntityId = selectedId,
            viewport = viewport
        )
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5_000),
        initialValue = MapScreenState()
    )
    private val usbSerialManager = MarauderUsbSerialManager(
        context = app,
        scope = viewModelScope,
        onData = ::onMarauderSerialData,
        onConnected = ::onMarauderConnected,
        onDiagnostic = ::appendDiagnostic
    )
    val marauderConnection = usbSerialManager.state

    init {
        usbSerialManager.refreshDevice()
        viewModelScope.launch(Dispatchers.IO) {
            repo.activeProjectProfile()?.let { _activeProjectSlug.value = it.slug }
        }
    }

    fun getDropboxToken(): String = prefs.getString("token", "") ?: ""
    fun getDropboxFolder(): String = prefs.getString("folder", "/WardriveAnalyzerProjects") ?: "/WardriveAnalyzerProjects"
    fun getDropboxZipName(): String = prefs.getString("zip_name", "") ?: ""

    fun saveDropboxConfig(token: String, folder: String, zipName: String = getDropboxZipName()) {
        prefs.edit()
            .putString("token", token.trim())
            .putString("folder", folder.trim().ifEmpty { "/WardriveAnalyzerProjects" })
            .putString("zip_name", zipName.trim())
            .apply()
        _dropboxStatus.value = "Dropbox config saved."
        refreshDropboxProjects()
    }

    fun refreshDropboxProjects() {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                _isRefreshingProjects.value = true
                val token = getDropboxToken()
                val root = getDropboxFolder()
                _dropboxStatus.value = "Refreshing Dropbox projects..."
                _mascotState.value = MarauderMascotState.SYNC
                _mascotMessage.value = "Marauder: Sweeping Dropbox project grid..."
                val profiles = dropboxService.listProjects(token, root, app.filesDir) { msg ->
                    _dropboxStatus.value = msg
                }
                val currentActive = repo.activeProjectProfile()?.slug
                val mapped = profiles.map {
                    val active = currentActive?.equals(it.slug, ignoreCase = true) == true
                    it.copy(isActive = active)
                }
                repo.replaceProjectProfiles(mapped)
                if (currentActive.isNullOrBlank() && mapped.isNotEmpty()) {
                    repo.setActiveProject(mapped.first().slug)
                    _activeProjectSlug.value = mapped.first().slug
                } else if (!currentActive.isNullOrBlank()) {
                    _activeProjectSlug.value = currentActive
                }
                _dropboxStatus.value = "Marauder: found ${mapped.size} projects."
                _mascotState.value = MarauderMascotState.SUCCESS
                _mascotMessage.value = "Marauder: Project manifest synced. Pick a target and run."
            } catch (e: Exception) {
                Log.e(tag, "Project refresh failed", e)
                _dropboxStatus.value = "Marauder: project refresh failed: ${e.message ?: e.javaClass.simpleName}"
                _mascotState.value = MarauderMascotState.WARNING
                _mascotMessage.value = "Marauder: Project refresh failed. Check token/path and retry."
            } finally {
                _isRefreshingProjects.value = false
            }
        }
    }

    fun setActiveProject(slug: String) {
        if (slug.isBlank()) return
        viewModelScope.launch(Dispatchers.IO) {
            repo.setActiveProject(slug)
            _activeProjectSlug.value = slug
            _dropboxStatus.value = "Marauder: active project set to $slug"
            _mascotMessage.value = "Marauder: Active project locked -> $slug"
        }
    }

    fun activateOrCreateProject(rawName: String): String {
        val slug = slugify(rawName)
        if (slug.isBlank()) return ""
        val display = rawName.trim().ifBlank { slug }
        viewModelScope.launch(Dispatchers.IO) {
            val root = getDropboxFolder().trim().ifBlank { "/WardriveAnalyzerProjects" }.trimEnd('/')
            val token = getDropboxToken().trim()
            repo.upsertProject(
                ProjectProfile(
                    slug = slug,
                    displayName = display,
                    dropboxPath = "$root/$slug/Project",
                    isActive = true,
                    lastSyncAt = System.currentTimeMillis()
                )
            )
            repo.setActiveProject(slug)
            _activeProjectSlug.value = slug
            _dropboxStatus.value = "Marauder: project target -> $slug"
            _mascotMessage.value = "Marauder: Project vector locked on $slug"
            if (token.isNotBlank()) {
                try {
                    dropboxService.ensureProjectInManifest(
                        token = token,
                        rootFolder = root,
                        projectSlug = slug,
                        displayName = display
                    ) { msg ->
                        _dropboxStatus.value = msg
                    }
                    refreshDropboxProjects()
                } catch (e: Exception) {
                    Log.e(tag, "Manifest update failed for project $slug", e)
                    _dropboxStatus.value = "Marauder: project created locally; manifest sync failed (${e.message ?: e.javaClass.simpleName})"
                    _mascotState.value = MarauderMascotState.WARNING
                    _mascotMessage.value = "Marauder: Manifest update failed. Local project is still active."
                }
            }
        }
        return slug
    }

    fun importUri(uri: Uri) {
        viewModelScope.launch {
            withContext(Dispatchers.IO) {
                val resolver = app.contentResolver
                val fileName = resolveDisplayName(uri)
                val lower = fileName.lowercase(Locale.US)
                if (!isSupportedImportName(lower)) {
                    _dropboxStatus.value =
                        "Unsupported file type: $fileName. Supported: .zip, .pcap, .pcapng, .cap, .csv, .log, .txt"
                    return@withContext
                }
                resolver.openInputStream(uri)?.use { stream ->
                    if (lower.endsWith(".zip")) {
                        importZipArchive(fileName, stream.readBytes())
                    } else if (lower.endsWith(".pcap") || lower.endsWith(".pcapng") || lower.endsWith(".cap")) {
                        repo.importPcap(fileName, stream)
                    } else {
                        BufferedReader(InputStreamReader(stream)).use { reader ->
                            repo.importLog(fileName, reader)
                        }
                    }
                }
            }
        }
    }

    fun refreshMarauderDevice() {
        usbSerialManager.refreshDevice()
    }

    fun connectMarauder() {
        _mascotState.value = MarauderMascotState.CONNECT
        _mascotMessage.value = "Marauder: Establishing serial uplink at 115200..."
        usbSerialManager.connect()
    }

    fun disconnectMarauder() {
        val sessionId = currentMarauderSessionId
        val logPath = currentMarauderRawLogFile?.absolutePath
        usbSerialManager.close(updateState = true)
        _mascotState.value = MarauderMascotState.WARNING
        _mascotMessage.value = "Marauder: Link dropped. Session sealed."
        if (sessionId != null) {
            viewModelScope.launch(Dispatchers.IO) {
                repo.finishMarauderSession(sessionId, logPath)
            }
            currentMarauderSessionId = null
        }
    }

    fun sendMarauderCommand(command: String) {
        usbSerialManager.writeCommand(command)
        val clean = command.trim()
        _lastCommand.value = clean
        _mascotState.value = if (clean.contains("scan", true) || clean.contains("wardrive", true)) {
            MarauderMascotState.SCAN
        } else {
            MarauderMascotState.CONNECT
        }
        _mascotMessage.value = "Marauder: Command uplinked -> $clean"
        appendTerminal("> $clean")
    }

    fun saveCurrentMarauderSessionLog(projectSlug: String? = null) {
        val sessionId = currentMarauderSessionId
        val lines = _marauderTerminal.value
        val rawFile = currentMarauderRawLogFile
        if (rawFile == null && sessionId == null && lines.isEmpty()) {
            appendDiagnostic("No live session log to save")
            return
        }
        viewModelScope.launch(Dispatchers.IO) {
            _mascotState.value = MarauderMascotState.EXPORT
            val file = rawFile ?: run {
                val outDir = File(app.filesDir, "marauder_sessions").apply { mkdirs() }
                val fallback = File(outDir, "marauder_session_${System.currentTimeMillis()}.txt")
                val logText = lines.joinToString("\n").ifBlank {
                    if (sessionId != null) repo.rawMarauderSessionLog(sessionId) else ""
                }
                fallback.writeText(logText)
                fallback
            }
            if (sessionId != null) repo.finishMarauderSession(sessionId, file.absolutePath)
            appendDiagnostic("Saved session log: ${file.name}")
            _mascotMessage.value = "Marauder: Session log archived -> ${file.name}"
            syncFileToProject(
                projectSlug = projectSlug,
                localFile = file,
                relativeProjectPath = "evidence/imports/marauder_sessions/${file.name}"
            )
            shareFile(file, "text/plain", "Share Marauder session log")
        }
    }

    fun shareMarauderDiagnosticsLog(projectSlug: String? = null) {
        viewModelScope.launch(Dispatchers.IO) {
            val file = marauderDiagnosticsLogFile()
            if (!file.exists()) {
                appendDiagnostic("No diagnostics log file exists yet")
            }
            syncFileToProject(
                projectSlug = projectSlug,
                localFile = file,
                relativeProjectPath = "runs/marauder/diagnostics.log"
            )
            shareFile(file, "text/plain", "Share Marauder diagnostics")
        }
    }

    fun importMarauderUris(uris: List<Uri>, projectSlug: String? = null) {
        viewModelScope.launch(Dispatchers.IO) {
            _mascotState.value = MarauderMascotState.SYNC
            var imported = 0
            uris.forEach { uri ->
                try {
                    if (importMarauderUri(uri, projectSlug)) imported += 1
                } catch (e: Exception) {
                    Log.w(tag, "Marauder file import failed: $uri", e)
                    appendDiagnostic("Import failed: ${e.message ?: e.javaClass.simpleName}")
                }
            }
            _marauderImportStatus.value = "Imported $imported files"
            _mascotState.value = MarauderMascotState.SUCCESS
            _mascotMessage.value = "Marauder: Imported $imported files into project flow."
        }
    }

    fun importMarauderTree(uri: Uri, projectSlug: String? = null) {
        viewModelScope.launch(Dispatchers.IO) {
            _mascotState.value = MarauderMascotState.SYNC
            val root = DocumentFile.fromTreeUri(app, uri)
            if (root == null) {
                _marauderImportStatus.value = "Could not open selected folder"
                return@launch
            }
            var imported = 0
            walkDocuments(root).forEach { doc ->
                val name = doc.name ?: return@forEach
                if (!MarauderFileClassifier.isLikelyMarauderFile(name)) return@forEach
                try {
                    if (importMarauderDocument(doc, projectSlug)) imported += 1
                } catch (e: Exception) {
                    Log.w(tag, "Marauder folder import failed: $name", e)
                    appendDiagnostic("Import failed for $name: ${e.message ?: e.javaClass.simpleName}")
                }
            }
            _marauderImportStatus.value = "Imported $imported files from folder"
            _mascotState.value = MarauderMascotState.SUCCESS
            _mascotMessage.value = "Marauder: Folder ingest complete ($imported files)."
        }
    }

    fun exportMarauderApCsv(projectSlug: String? = null) {
        viewModelScope.launch(Dispatchers.IO) {
            _mascotState.value = MarauderMascotState.EXPORT
            val rows = repo.marauderApRecordsSnapshot()
            val file = File(app.cacheDir, "marauder_ap_records_${System.currentTimeMillis()}.csv")
            file.writeText(buildString {
                appendLine("ssid,bssid,channel,rssi,encryption,source_type,raw_line")
                rows.forEach { row ->
                    appendCsvLine(row.ssid, row.bssid, row.channel, row.rssi, row.encryption, row.sourceType, row.rawLine)
                }
            })
            syncFileToProject(
                projectSlug = projectSlug,
                localFile = file,
                relativeProjectPath = "exports/marauder/marauder_ap_records.csv"
            )
            shareFile(file, "text/csv", "Share Marauder AP CSV")
            _mascotState.value = MarauderMascotState.SUCCESS
            _mascotMessage.value = "Marauder: AP CSV exported and ready to route."
        }
    }

    fun exportMarauderWardriveCsv(projectSlug: String? = null) {
        viewModelScope.launch(Dispatchers.IO) {
            _mascotState.value = MarauderMascotState.EXPORT
            val rows = repo.marauderWardriveRecordsSnapshot()
            val file = File(app.cacheDir, "marauder_wardrive_${System.currentTimeMillis()}.csv")
            file.writeText(buildString {
                appendLine("ssid,bssid,rssi,channel,encryption,latitude,longitude,accuracy,timestamp,source_type")
                rows.forEach { row ->
                    appendCsvLine(
                        row.ssid,
                        row.bssid,
                        row.rssi,
                        row.channel,
                        row.encryption,
                        row.latitude,
                        row.longitude,
                        row.accuracy,
                        row.timestamp,
                        row.sourceType
                    )
                }
            })
            syncFileToProject(
                projectSlug = projectSlug,
                localFile = file,
                relativeProjectPath = "exports/marauder/marauder_wardrive.csv"
            )
            shareFile(file, "text/csv", "Share Marauder wardrive CSV")
            _mascotState.value = MarauderMascotState.SUCCESS
            _mascotMessage.value = "Marauder: Wardrive CSV exported."
        }
    }

    fun exportMarauderWardriveJson(projectSlug: String? = null) {
        viewModelScope.launch(Dispatchers.IO) {
            _mascotState.value = MarauderMascotState.EXPORT
            val rows = repo.marauderWardriveRecordsSnapshot()
            val file = File(app.cacheDir, "marauder_wardrive_${System.currentTimeMillis()}.json")
            file.writeText(buildString {
                append("[\n")
                rows.forEachIndexed { index, row ->
                    append("  {")
                    append("\"ssid\":\"${jsonEscape(row.ssid.orEmpty())}\",")
                    append("\"bssid\":\"${jsonEscape(row.bssid.orEmpty())}\",")
                    append("\"rssi\":${row.rssi ?: "null"},")
                    append("\"channel\":${row.channel ?: "null"},")
                    append("\"latitude\":${row.latitude ?: "null"},")
                    append("\"longitude\":${row.longitude ?: "null"},")
                    append("\"timestamp\":${row.timestamp ?: "null"}")
                    append("}")
                    if (index != rows.lastIndex) append(",")
                    append("\n")
                }
                append("]\n")
            })
            syncFileToProject(
                projectSlug = projectSlug,
                localFile = file,
                relativeProjectPath = "exports/marauder/marauder_wardrive.json"
            )
            shareFile(file, "application/json", "Share Marauder wardrive JSON")
            _mascotState.value = MarauderMascotState.SUCCESS
            _mascotMessage.value = "Marauder: Wardrive JSON exported."
        }
    }

    fun shareImportedMarauderFile(item: MarauderImportedFileEntity) {
        val file = File(item.storedPath)
        val type = when (item.fileType) {
            MarauderImportFileType.PCAP.name.lowercase() -> "application/vnd.tcpdump.pcap"
            MarauderImportFileType.WARDRIVE_CSV.name.lowercase() -> "text/csv"
            MarauderImportFileType.LOG.name.lowercase() -> "text/plain"
            else -> "application/octet-stream"
        }
        if (file.exists()) shareFile(file, type, "Share ${item.originalName}")
    }

    fun syncFromDropbox() {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                _isSyncingDropbox.value = true
                _mascotState.value = MarauderMascotState.SYNC
                _mascotMessage.value = "Marauder: Pulling selected project from Dropbox..."
                val token = getDropboxToken()
                val root = getDropboxFolder()
                val zipName = getDropboxZipName()
                val activeSlug = repo.activeProjectProfile()?.slug ?: _activeProjectSlug.value
                if (activeSlug.isNotBlank()) {
                    val pull = dropboxService.pullProject(token, root, activeSlug, app.filesDir) { msg ->
                        _dropboxStatus.value = msg
                    }
                    repo.addSyncRecord(
                        SyncRecord(
                            projectSlug = activeSlug,
                            direction = "pull",
                            path = "Project",
                            status = "success",
                            timestamp = System.currentTimeMillis(),
                            conflictFlag = pull.conflicts > 0,
                            message = "Downloaded ${pull.filesDownloaded} files, conflicts=${pull.conflicts}"
                        )
                    )
                    val imported = importDirectory(File(pull.localProjectDir))
                    _dropboxStatus.value =
                        "Marauder pull complete: files=${pull.filesDownloaded}, conflicts=${pull.conflicts}, parsed logs=${imported.logRows}, pcap_packets=${imported.pcapPackets}"
                    _mascotState.value = MarauderMascotState.SUCCESS
                    _mascotMessage.value = "Marauder: Pull complete. Project mirror updated."
                    _syncCompletedSignal.value = System.currentTimeMillis()
                    return@launch
                }

                // Legacy fallback while migrating older accounts.
                val outDir = dropboxService.syncFromDropbox(token, root, zipName, app.filesDir) { msg ->
                    _dropboxStatus.value = msg
                }
                val imported = importDirectory(outDir)
                _dropboxStatus.value =
                    "Legacy sync complete: files=${imported.files}, logs=${imported.logRows}, pcap_packets=${imported.pcapPackets}"
                _mascotState.value = MarauderMascotState.SUCCESS
                _mascotMessage.value = "Marauder: Legacy archive sync complete."
                _syncCompletedSignal.value = System.currentTimeMillis()
            } catch (e: Exception) {
                Log.e(tag, "Dropbox sync failed", e)
                val detail = e.message ?: e.javaClass.simpleName
                withContext(Dispatchers.Main) {
                    _dropboxStatus.value = "Dropbox sync failed: $detail"
                }
                _mascotState.value = MarauderMascotState.WARNING
                _mascotMessage.value = "Marauder: Sync failed. Check diagnostics and try again."
            } finally {
                _isSyncingDropbox.value = false
            }
        }
    }

    fun deleteEvidence(ids: Set<Long>) {
        viewModelScope.launch(Dispatchers.IO) {
            repo.deleteEvidence(ids.toList())
            _dropboxStatus.value = "Deleted ${ids.size} evidence item(s)."
        }
    }

    fun deleteRuns(ids: Set<Long>) {
        viewModelScope.launch(Dispatchers.IO) {
            repo.deleteRuns(ids.toList())
            _dropboxStatus.value = "Deleted ${ids.size} run(s)."
        }
    }

    fun setMapFilter(filter: MapEntityTypeFilter) {
        _mapFilter.value = filter
    }

    fun selectMapEntity(entityId: String?) {
        _selectedMapEntityId.value = entityId
    }

    fun setMapViewportDelta(dx: Float, dy: Float) {
        val current = _mapViewport.value
        _mapViewport.value = current.copy(
            offsetX = (current.offsetX + dx).coerceIn(-300f, 300f),
            offsetY = (current.offsetY + dy).coerceIn(-300f, 300f)
        )
    }

    fun scaleMapViewport(zoomDelta: Float) {
        if (!zoomDelta.isFinite()) return
        val current = _mapViewport.value
        val target = (current.zoom * zoomDelta).coerceIn(0.65f, 2.6f)
        if ((target * 100f).roundToInt() == (current.zoom * 100f).roundToInt()) return
        _mapViewport.value = current.copy(zoom = target)
    }

    private suspend fun importDirectory(root: File): ImportSummary {
        var files = 0
        var logRows = 0
        var pcapPackets = 0
        val candidates = root.walkTopDown().filter { it.isFile }.toList()
        val total = candidates.size
        candidates.forEachIndexed { idx, file ->
                _dropboxStatus.value = "Parsing synced evidence... (${idx + 1}/$total) ${file.name}"
                val lower = file.name.lowercase(Locale.US)
                try {
                    when {
                        lower.endsWith(".zip") -> {
                            files += 1
                            importZipArchive(file.name, file.readBytes())
                        }
                        lower.endsWith(".pcap") || lower.endsWith(".cap") || lower.endsWith(".pcapng") -> {
                            files += 1
                            file.inputStream().use { stream ->
                                pcapPackets += repo.importPcap(file.name, stream)
                            }
                        }
                        lower.endsWith(".csv") || lower.endsWith(".log") || lower.endsWith(".txt") -> {
                            if (!shouldParseAsEvidenceFile(file.name)) return@forEachIndexed
                            if (file.length() > 25L * 1024L * 1024L) {
                                Log.w(tag, "Skipping oversized text-like file: ${file.absolutePath} (${file.length()} bytes)")
                                return@forEachIndexed
                            }
                            files += 1
                            file.bufferedReader().use { reader ->
                                logRows += repo.importLog(file.name, reader)
                            }
                        }
                    }
                } catch (e: Exception) {
                    Log.w(tag, "Skipping synced file due to parse error: ${file.absolutePath}", e)
                }
            }
        return ImportSummary(files = files, logRows = logRows, pcapPackets = pcapPackets)
    }

    private suspend fun importZipArchive(archiveName: String, bytes: ByteArray) {
        var logRows = 0
        var pcapPackets = 0
        var entries = 0
        ZipInputStream(ByteArrayInputStream(bytes)).use { zis ->
            var entry = zis.nextEntry
            while (entry != null) {
                if (!entry.isDirectory) {
                    entries += 1
                    val entryName = entry.name.substringAfterLast('/').ifBlank { "entry_$entries" }
                    val lower = entryName.lowercase(Locale.US)
                    val data = readEntryBytes(zis)
                    try {
                        when {
                            lower.endsWith(".pcap") || lower.endsWith(".cap") || lower.endsWith(".pcapng") -> {
                                pcapPackets += repo.importPcap(entryName, ByteArrayInputStream(data))
                            }
                            lower.endsWith(".csv") || lower.endsWith(".log") || lower.endsWith(".txt") -> {
                                if (shouldParseAsEvidenceFile(entryName)) {
                                    BufferedReader(InputStreamReader(ByteArrayInputStream(data))).use { reader ->
                                        logRows += repo.importLog(entryName, reader)
                                    }
                                }
                            }
                        }
                    } catch (e: Exception) {
                        Log.w(tag, "Skipping zip entry due to parse error: $entryName", e)
                    }
                }
                zis.closeEntry()
                entry = zis.nextEntry
            }
        }
        _dropboxStatus.value = "Imported $archiveName: entries=$entries logs=$logRows pcap_packets=$pcapPackets"
    }

    private fun readEntryBytes(zis: ZipInputStream): ByteArray {
        val out = ByteArrayOutputStream()
        val buf = ByteArray(8192)
        while (true) {
            val n = zis.read(buf)
            if (n <= 0) break
            out.write(buf, 0, n)
        }
        return out.toByteArray()
    }

    private fun resolveDisplayName(uri: Uri): String {
        val resolver = app.contentResolver
        try {
            resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
                if (c.moveToFirst()) {
                    val idx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if (idx >= 0) {
                        val name = c.getString(idx)
                        if (!name.isNullOrBlank()) return name
                    }
                }
            }
        } catch (_: Exception) {
        }
        return uri.lastPathSegment ?: "import.csv"
    }

    private data class ImportSummary(
        val files: Int,
        val logRows: Int,
        val pcapPackets: Int
    )

    private fun isSupportedImportName(lowerName: String): Boolean {
        val ext = lowerName.substringAfterLast('.', "")
        return ext in supportedExtensions
    }

    private fun shouldParseAsEvidenceFile(name: String): Boolean {
        val n = name.lowercase(Locale.US)
        if (n == "wardrive_master.csv") return true
        if (n.endsWith(".log")) return true
        if (n.contains("wardrive") || n.contains("wigle") || n.contains("recon") || n.contains("beacon")) {
            if (n.endsWith(".csv") || n.endsWith(".txt")) return true
        }
        if (n.contains("summary") || n.contains("pcap_bssid_master") || n.contains("pcap_station_master") || n.contains("pcap_per_file_summary")) {
            return false
        }
        return false
    }

    private fun onMarauderConnected(device: MarauderDeviceInfo) {
        val sessionId = UUID.randomUUID().toString()
        currentMarauderSessionId = sessionId
        lastTerminalBaseLine = null
        lastTerminalRepeatCount = 0
        currentMarauderRawLogFile = File(marauderSessionLogDir(), "marauder_session_${sessionId}.txt").also {
            it.parentFile?.mkdirs()
            it.writeText("Marauder session $sessionId\nDevice: ${device.deviceName} VID=${device.vendorId} PID=${device.productId}\nStarted: ${System.currentTimeMillis()}\n\n")
        }
        _marauderTerminal.value = emptyList()
        _mascotState.value = MarauderMascotState.CONNECT
        _mascotMessage.value = "Marauder: Link live on ${device.deviceName} at 115200."
        viewModelScope.launch(Dispatchers.IO) {
            repo.startMarauderSession(sessionId, device)
        }
    }

    private fun onMarauderSerialData(text: String) {
        appendRawMarauderLog(text)
        serialCarry.append(text.replace("\r\n", "\n").replace('\r', '\n'))
        val lines = serialCarry.toString().split('\n')
        serialCarry.clear()
        if (!text.endsWith("\n") && lines.isNotEmpty()) {
            serialCarry.append(lines.last())
        }
        val complete = if (text.endsWith("\n")) lines else lines.dropLast(1)
        complete.filter { it.isNotBlank() }.forEach { line ->
            appendTerminal(line)
            val parsed = marauderParser.parseLine(line)
            val sessionId = currentMarauderSessionId
            if (sessionId != null) {
                viewModelScope.launch(Dispatchers.IO) {
                    repo.appendMarauderSerialLine(sessionId, line, parsed)
                }
            }
        }
    }

    private fun appendTerminal(line: String) {
        synchronized(terminalUiLock) {
            terminalUiBuffer += line
        }
        if (terminalFlushJob?.isActive == true) return
        terminalFlushJob = viewModelScope.launch(Dispatchers.Main) {
            delay(120L)
            flushTerminalBuffer()
            terminalFlushJob = null
        }
    }

    private fun flushTerminalBuffer() {
        val batch = synchronized(terminalUiLock) {
            if (terminalUiBuffer.isEmpty()) return
            val copy = terminalUiBuffer.toList()
            terminalUiBuffer.clear()
            copy
        }
        val current = _marauderTerminal.value.toMutableList()
        batch.forEach { line ->
            val normalized = line.trim()
            if (normalized.isNotEmpty() && normalized == lastTerminalBaseLine && current.isNotEmpty()) {
                lastTerminalRepeatCount += 1
                current[current.lastIndex] = "$normalized  [x$lastTerminalRepeatCount]"
            } else {
                lastTerminalBaseLine = normalized.ifEmpty { null }
                lastTerminalRepeatCount = 1
                current += line
            }
        }
        _marauderTerminal.value = current.takeLast(220)
    }

    private fun appendDiagnostic(message: String) {
        val line = "${java.text.DateFormat.getDateTimeInstance().format(java.util.Date())}  $message"
        appendDiagnosticLogLine(line)
        _marauderDiagnostics.value =
            (_marauderDiagnostics.value + line)
                .takeLast(120)
    }

    private fun appendRawMarauderLog(text: String) {
        val file = currentMarauderRawLogFile ?: return
        synchronized(marauderLogLock) {
            try {
                file.appendText(text)
            } catch (e: Exception) {
                Log.w(tag, "Failed to append Marauder raw log", e)
            }
        }
    }

    private fun appendDiagnosticLogLine(line: String) {
        synchronized(marauderLogLock) {
            try {
                val file = marauderDiagnosticsLogFile()
                file.parentFile?.mkdirs()
                file.appendText(line + "\n")
            } catch (e: Exception) {
                Log.w(tag, "Failed to append Marauder diagnostics log", e)
            }
        }
    }

    private fun marauderSessionLogDir(): File =
        File(app.filesDir, "marauder_sessions").apply { mkdirs() }

    private fun marauderDiagnosticsLogFile(): File =
        File(File(app.filesDir, "marauder_logs").apply { mkdirs() }, "diagnostics.log")

    private suspend fun syncFileToProject(
        projectSlug: String?,
        localFile: File,
        relativeProjectPath: String
    ) {
        val token = getDropboxToken().trim()
        val slug = projectSlug?.takeIf { it.isNotBlank() }
            ?: repo.activeProjectProfile()?.slug
            ?: _activeProjectSlug.value.takeIf { it.isNotBlank() }
        if (token.isBlank() || slug.isNullOrBlank() || !localFile.exists()) return
        try {
            _mascotState.value = MarauderMascotState.SYNC
            val record = dropboxService.pushProjectArtifact(
                token = token,
                rootFolder = getDropboxFolder(),
                projectSlug = slug,
                localFile = localFile,
                relativeProjectPath = relativeProjectPath
            ) { msg ->
                _dropboxStatus.value = msg
            }
            repo.addSyncRecord(record)
            _dropboxStatus.value = "Marauder: synced ${record.path} to project $slug"
            _mascotState.value = MarauderMascotState.SUCCESS
            _mascotMessage.value = "Marauder: Synced ${record.path} to $slug"
        } catch (e: Exception) {
            Log.e(tag, "Project sync push failed", e)
            repo.addSyncRecord(
                SyncRecord(
                    projectSlug = slug,
                    direction = "push",
                    path = relativeProjectPath,
                    status = "error",
                    timestamp = System.currentTimeMillis(),
                    conflictFlag = false,
                    message = e.message ?: e.javaClass.simpleName
                )
            )
            _dropboxStatus.value = "Marauder sync push failed: ${e.message ?: e.javaClass.simpleName}"
            _mascotState.value = MarauderMascotState.WARNING
            _mascotMessage.value = "Marauder: Sync push failed. Check diagnostics."
        }
    }

    private suspend fun importMarauderUri(uri: Uri, projectSlug: String?): Boolean {
        val name = resolveDisplayName(uri)
        val resolver = app.contentResolver
        resolver.openInputStream(uri)?.use { input ->
            val importId = UUID.randomUUID().toString()
            val fileType = MarauderFileClassifier.classify(name)
            val dest = destinationFile(importId, name)
            dest.outputStream().use { output -> input.copyTo(output) }
            recordImportedMarauderFile(importId, name, dest, fileType, projectSlug)
            return true
        }
        return false
    }

    private suspend fun importMarauderDocument(doc: DocumentFile, projectSlug: String?): Boolean {
        val uri = doc.uri
        val name = doc.name ?: return false
        app.contentResolver.openInputStream(uri)?.use { input ->
            val importId = UUID.randomUUID().toString()
            val fileType = MarauderFileClassifier.classify(name)
            val dest = destinationFile(importId, name)
            dest.outputStream().use { output -> input.copyTo(output) }
            recordImportedMarauderFile(importId, name, dest, fileType, projectSlug)
            return true
        }
        return false
    }

    private suspend fun recordImportedMarauderFile(
        importId: String,
        name: String,
        file: File,
        fileType: MarauderImportFileType,
        projectSlug: String?
    ) {
        val records = if (fileType == MarauderImportFileType.WARDRIVE_CSV || fileType == MarauderImportFileType.LOG) {
            parseMarauderTextFile(file)
        } else {
            emptyList()
        }
        repo.recordMarauderImport(
            importId = importId,
            originalName = name,
            storedPath = file.absolutePath,
            sizeBytes = file.length(),
            sha256 = Sha256.hashFile(file),
            fileType = fileType,
            records = records
        )
        if (fileType == MarauderImportFileType.PCAP) {
            file.inputStream().use { repo.importPcap(name, it) }
        } else if (records.isEmpty() && file.length() < 25L * 1024L * 1024L && fileType != MarauderImportFileType.UNKNOWN) {
            file.bufferedReader().use { repo.importLog(name, it) }
        }
        syncFileToProject(
            projectSlug = projectSlug,
            localFile = file,
            relativeProjectPath = "evidence/imports/marauder_sd/${file.name}"
        )
        appendDiagnostic("File imported: $name type=${fileType.name.lowercase()} records=${records.size}")
    }

    private fun parseMarauderTextFile(file: File): List<com.wardrive.analyzer.android.marauder.MarauderWardriveRecord> {
        if (file.length() > 25L * 1024L * 1024L) {
            appendDiagnostic("Skipped parse for oversized text file: ${file.name}")
            return emptyList()
        }
        return try {
            file.bufferedReader().use { marauderCsvParser.parse(it) }
        } catch (e: Exception) {
            Log.w(tag, "Marauder parse failed for ${file.name}", e)
            appendDiagnostic("Parse failed for ${file.name}: ${e.message ?: e.javaClass.simpleName}")
            emptyList()
        }
    }

    private fun destinationFile(importId: String, originalName: String): File {
        val dir = File(app.filesDir, "marauder_imports/$importId").apply { mkdirs() }
        return File(dir, sanitizeFileName(originalName))
    }

    private fun sanitizeFileName(name: String): String =
        name.replace(Regex("""[\\/:*?"<>|]"""), "_").ifBlank { "marauder_import.dat" }

    private fun walkDocuments(root: DocumentFile): List<DocumentFile> {
        val out = mutableListOf<DocumentFile>()
        fun visit(doc: DocumentFile) {
            if (doc.isDirectory) {
                doc.listFiles().forEach(::visit)
            } else if (doc.isFile) {
                out += doc
            }
        }
        visit(root)
        return out
    }

    private fun shareFile(file: File, mimeType: String, chooserTitle: String) {
        val uri = FileProvider.getUriForFile(app, "com.wardrive.analyzer.android.fileprovider", file)
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = mimeType
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        val chooser = Intent.createChooser(intent, chooserTitle).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        viewModelScope.launch(Dispatchers.Main) {
            app.startActivity(chooser)
        }
    }

    private fun StringBuilder.appendCsvLine(vararg values: Any?) {
        appendLine(values.joinToString(",") { csvEscape(it?.toString().orEmpty()) })
    }

    private fun csvEscape(value: String): String {
        val escaped = value.replace("\"", "\"\"")
        return if (escaped.any { it == ',' || it == '"' || it == '\n' }) "\"$escaped\"" else escaped
    }

    private fun jsonEscape(value: String): String =
        value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")

    override fun onCleared() {
        flushTerminalBuffer()
        usbSerialManager.dispose()
        super.onCleared()
    }

    companion object {
        private val supportedExtensions = setOf("zip", "pcap", "pcapng", "cap", "csv", "log", "txt")
        private val slugRegex = Regex("""[^a-z0-9_-]""")

        private fun slugify(value: String): String {
            val lowered = value.trim().lowercase(Locale.US).replace(' ', '-')
            val clean = lowered.replace(slugRegex, "-").replace(Regex("-+"), "-").trim('-')
            return clean.take(64)
        }

        fun factory(app: WardriveApplication): ViewModelProvider.Factory =
            object : ViewModelProvider.Factory {
                override fun <T : ViewModel> create(modelClass: Class<T>): T {
                    @Suppress("UNCHECKED_CAST")
                    return WardriveViewModel(app) as T
                }
            }
    }
}

private data class Quadruple<A, B, C, D>(
    val first: A,
    val second: B,
    val third: C,
    val fourth: D
)
