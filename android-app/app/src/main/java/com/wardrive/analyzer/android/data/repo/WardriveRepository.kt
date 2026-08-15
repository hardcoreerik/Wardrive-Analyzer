package com.wardrive.analyzer.android.data.repo

import com.wardrive.analyzer.android.data.db.WardriveDatabase
import com.wardrive.analyzer.android.data.model.EvidenceEntity
import com.wardrive.analyzer.android.data.model.MarauderApRecordEntity
import com.wardrive.analyzer.android.data.model.MarauderImportedFileEntity
import com.wardrive.analyzer.android.data.model.MarauderLiveSessionEntity
import com.wardrive.analyzer.android.data.model.MarauderSerialLogEntity
import com.wardrive.analyzer.android.data.model.MarauderStationRecordEntity
import com.wardrive.analyzer.android.data.model.MarauderWardriveRecordEntity
import com.wardrive.analyzer.android.data.model.ProjectProfileEntity
import com.wardrive.analyzer.android.data.model.ReportEntity
import com.wardrive.analyzer.android.data.model.RunEntity
import com.wardrive.analyzer.android.data.model.SyncRecordEntity
import com.wardrive.analyzer.android.ingest.PcapIngestService
import com.wardrive.analyzer.android.ingest.WardriveLogParser
import com.wardrive.analyzer.android.marauder.MarauderDeviceInfo
import com.wardrive.analyzer.android.marauder.MarauderImportFileType
import com.wardrive.analyzer.android.marauder.MarauderParseResult
import com.wardrive.analyzer.android.marauder.MarauderWardriveRecord
import com.wardrive.analyzer.android.sync.ProjectProfile
import com.wardrive.analyzer.android.sync.SyncRecord
import java.io.BufferedReader
import java.io.InputStream
import java.util.UUID

class WardriveRepository(
    private val db: WardriveDatabase,
    private val parser: WardriveLogParser = WardriveLogParser(),
    private val pcapIngestService: PcapIngestService = PcapIngestService()
) {
    val evidence = db.evidenceDao().observeAll()
    val evidenceCount = db.evidenceDao().observeCount()
    val openCount = db.evidenceDao().observeOpenCount()
    val runs = db.runDao().observeAll()
    val reports = db.reportDao().observeAll()
    val marauderImportedFiles = db.marauderDao().observeImportedFiles()
    val marauderApRecords = db.marauderDao().observeApRecords()
    val marauderWardriveRecords = db.marauderDao().observeWardriveRecords()
    val projectProfiles = db.marauderDao().observeProjects()
    val syncRecords = db.marauderDao().observeSyncRecords()

    suspend fun importLog(sourceName: String, reader: BufferedReader): Int {
        val parsed = parser.parse(reader)
        if (parsed.isEmpty()) return 0
        val batch = UUID.randomUUID().toString()
        val importedAt = System.currentTimeMillis()
        val rows = parsed.map {
            EvidenceEntity(
                sourceName = sourceName,
                bssid = it.bssid,
                ssid = it.ssid,
                security = it.security,
                channel = it.channel,
                rssi = it.rssi,
                latitude = it.latitude,
                longitude = it.longitude,
                seenAt = it.seenAt,
                importedAt = importedAt,
                importBatch = batch
            )
        }
        db.evidenceDao().insertAll(rows)
        val openNetworks = rows.count { it.security.contains("OPEN", ignoreCase = true) }
        val hiddenNetworks = rows.count { it.ssid == "<hidden>" }
        val risk = computeRiskScore(
            openNetworks = openNetworks,
            hiddenNetworks = hiddenNetworks,
            pcapEapol = 0,
            apCount = rows.map { it.bssid }.toSet().size,
            stationCount = 0
        )

        val runId = db.runDao().insert(
            RunEntity(
                name = "Import $sourceName",
                createdAt = importedAt,
                evidenceCount = rows.size,
                openNetworkCount = openNetworks,
                hiddenSsidCount = hiddenNetworks,
                pcapPacketCount = 0,
                pcapEapolCount = 0,
                pcapBytes = 0,
                pcapApCount = 0,
                pcapStationCount = 0,
                handshakeConfidence = "NONE",
                riskScore = risk
            )
        )
        db.reportDao().insertAll(
            listOf(
                ReportEntity(
                    runId = runId,
                    reportType = "summary",
                    title = "Run Summary",
                    body = "Imported ${rows.size} rows from $sourceName. Risk score: $risk/100.",
                    createdAt = importedAt
                )
            )
        )
        return rows.size
    }

    suspend fun importPcap(sourceName: String, inputStream: InputStream): Int {
        val summary = pcapIngestService.summarize(inputStream)
        val importedAt = System.currentTimeMillis()
        val risk = computeRiskScore(
            openNetworks = 0,
            hiddenNetworks = 0,
            pcapEapol = summary.eapolCount,
            apCount = summary.apCount,
            stationCount = summary.stationCount,
            handshakeConfidence = summary.handshakeConfidence
        )
        val runId = db.runDao().insert(
            RunEntity(
                name = "PCAP $sourceName",
                createdAt = importedAt,
                evidenceCount = 0,
                openNetworkCount = 0,
                hiddenSsidCount = 0,
                pcapPacketCount = summary.packetCount,
                pcapEapolCount = summary.eapolCount,
                pcapBytes = summary.totalBytes,
                pcapApCount = summary.apCount,
                pcapStationCount = summary.stationCount,
                handshakeConfidence = summary.handshakeConfidence,
                riskScore = risk
            )
        )
        db.reportDao().insertAll(
            listOf(
                ReportEntity(
                    runId = runId,
                    reportType = "pcap_summary",
                    title = "PCAP Summary",
                    body = "Packets=${summary.packetCount}, EAPOL=${summary.eapolCount}, Handshake=${summary.handshakeConfidence}, APs=${summary.apCount}, Stations=${summary.stationCount}, MgmtFrames=${summary.managementFrameCount}, Bytes=${summary.totalBytes}. Risk score: $risk/100.",
                    createdAt = importedAt
                )
            )
        )
        return summary.packetCount
    }

    suspend fun deleteEvidence(ids: List<Long>) {
        if (ids.isEmpty()) return
        db.evidenceDao().deleteByIds(ids)
    }

    suspend fun deleteRuns(ids: List<Long>) {
        if (ids.isEmpty()) return
        db.reportDao().deleteByRunIds(ids)
        db.runDao().deleteByIds(ids)
    }

    suspend fun startMarauderSession(sessionId: String, device: MarauderDeviceInfo?) {
        db.marauderDao().insertSession(
            MarauderLiveSessionEntity(
                sessionId = sessionId,
                startedAt = System.currentTimeMillis(),
                endedAt = null,
                deviceName = device?.deviceName,
                vendorId = device?.vendorId,
                productId = device?.productId,
                baudRate = 115200,
                status = "connected",
                savedLogPath = null
            )
        )
    }

    suspend fun finishMarauderSession(sessionId: String, savedLogPath: String?) {
        val existing = db.marauderDao().getSession(sessionId) ?: return
        db.marauderDao().updateSession(
            existing.copy(
                endedAt = System.currentTimeMillis(),
                status = "closed",
                savedLogPath = savedLogPath ?: existing.savedLogPath
            )
        )
    }

    suspend fun appendMarauderSerialLine(sessionId: String, rawLine: String, parsed: MarauderParseResult) {
        val now = System.currentTimeMillis()
        db.marauderDao().insertSerialLog(
            MarauderSerialLogEntity(
                sessionId = sessionId,
                rawLine = rawLine,
                seenAt = now
            )
        )
        parsed.accessPoint?.let {
            db.marauderDao().insertAp(
                MarauderApRecordEntity(
                    sourceType = "usb_live",
                    sessionId = sessionId,
                    importId = null,
                    ssid = it.ssid,
                    bssid = it.bssid,
                    channel = it.channel,
                    rssi = it.rssi,
                    encryption = it.encryption,
                    rawLine = it.rawLine,
                    firstSeen = it.firstSeen,
                    lastSeen = it.lastSeen
                )
            )
        }
        parsed.station?.let {
            db.marauderDao().insertStation(
                MarauderStationRecordEntity(
                    sourceType = "usb_live",
                    sessionId = sessionId,
                    importId = null,
                    mac = it.mac,
                    associatedBssid = it.associatedBssid,
                    rssi = it.rssi,
                    channel = it.channel,
                    rawLine = it.rawLine,
                    firstSeen = it.firstSeen,
                    lastSeen = it.lastSeen
                )
            )
        }
        parsed.wardriveRecord?.let { record ->
            db.marauderDao().insertWardriveRecord(record.toEntity("usb_live", sessionId, null))
        }
    }

    suspend fun recordMarauderImport(
        importId: String,
        originalName: String,
        storedPath: String,
        sizeBytes: Long,
        sha256: String,
        fileType: MarauderImportFileType,
        records: List<MarauderWardriveRecord>
    ) {
        db.marauderDao().insertImportedFile(
            MarauderImportedFileEntity(
                importId = importId,
                originalName = originalName,
                storedPath = storedPath,
                sizeBytes = sizeBytes,
                sha256 = sha256,
                importedAt = System.currentTimeMillis(),
                fileType = fileType.name.lowercase(),
                parsedRecordCount = records.size
            )
        )
        if (records.isNotEmpty()) {
            db.marauderDao().insertWardriveRecords(
                records.map { it.toEntity("sd_import", null, importId) }
            )
        }
    }

    suspend fun rawMarauderSessionLog(sessionId: String): String =
        db.marauderDao().getRawLogLines(sessionId).joinToString("\n")

    suspend fun marauderApRecordsSnapshot(): List<MarauderApRecordEntity> =
        db.marauderDao().getApRecords()

    suspend fun marauderWardriveRecordsSnapshot(): List<MarauderWardriveRecordEntity> =
        db.marauderDao().getWardriveRecords()

    suspend fun replaceProjectProfiles(projects: List<ProjectProfile>) {
        db.marauderDao().upsertProjects(
            projects.map {
                ProjectProfileEntity(
                    slug = it.slug,
                    displayName = it.displayName,
                    dropboxPath = it.dropboxPath,
                    isActive = it.isActive,
                    lastSyncAt = it.lastSyncAt
                )
            }
        )
    }

    suspend fun upsertProject(project: ProjectProfile) {
        db.marauderDao().upsertProject(
            ProjectProfileEntity(
                slug = project.slug,
                displayName = project.displayName,
                dropboxPath = project.dropboxPath,
                isActive = project.isActive,
                lastSyncAt = project.lastSyncAt
            )
        )
    }

    suspend fun projectProfilesSnapshot(): List<ProjectProfileEntity> =
        db.marauderDao().getProjects()

    suspend fun setActiveProject(slug: String) {
        db.marauderDao().setActiveProject(slug)
    }

    suspend fun activeProjectProfile(): ProjectProfileEntity? =
        db.marauderDao().getActiveProject()

    suspend fun addSyncRecord(record: SyncRecord) {
        db.marauderDao().insertSyncRecord(
            SyncRecordEntity(
                projectSlug = record.projectSlug,
                direction = record.direction,
                path = record.path,
                status = record.status,
                timestamp = record.timestamp,
                conflictFlag = record.conflictFlag,
                message = record.message
            )
        )
    }

    private fun computeRiskScore(
        openNetworks: Int,
        hiddenNetworks: Int,
        pcapEapol: Int,
        apCount: Int,
        stationCount: Int,
        handshakeConfidence: String = "NONE"
    ): Int {
        val openRisk = (openNetworks * 3).coerceAtMost(35)
        val hiddenRisk = (hiddenNetworks * 2).coerceAtMost(15)
        val eapolRisk = (pcapEapol / 2).coerceAtMost(30)
        val densityRisk = ((apCount + stationCount) / 5).coerceAtMost(20)
        val handshakeRisk = when (handshakeConfidence) {
            "4WAY" -> 20
            "PARTIAL" -> 10
            "EAPOL" -> 4
            else -> 0
        }
        return (openRisk + hiddenRisk + eapolRisk + densityRisk + handshakeRisk).coerceIn(0, 100)
    }

    private fun MarauderWardriveRecord.toEntity(
        sourceType: String,
        sessionId: String?,
        importId: String?
    ): MarauderWardriveRecordEntity =
        MarauderWardriveRecordEntity(
            sourceType = sourceType,
            sessionId = sessionId,
            importId = importId,
            ssid = ssid,
            bssid = bssid,
            rssi = rssi,
            channel = channel,
            encryption = encryption,
            latitude = latitude,
            longitude = longitude,
            accuracy = accuracy,
            timestamp = timestamp,
            rawLine = rawLine
        )
}
