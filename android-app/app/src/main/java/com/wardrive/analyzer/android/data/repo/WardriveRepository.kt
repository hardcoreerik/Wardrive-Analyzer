package com.wardrive.analyzer.android.data.repo

import com.wardrive.analyzer.android.data.db.WardriveDatabase
import com.wardrive.analyzer.android.data.model.EvidenceEntity
import com.wardrive.analyzer.android.data.model.ReportEntity
import com.wardrive.analyzer.android.data.model.RunEntity
import com.wardrive.analyzer.android.ingest.WardriveLogParser
import kotlinx.coroutines.flow.Flow
import java.io.BufferedReader
import java.util.UUID

class WardriveRepository(
    private val db: WardriveDatabase,
    private val parser: WardriveLogParser = WardriveLogParser()
) {
    val evidence = db.evidenceDao().observeAll()
    val evidenceCount = db.evidenceDao().observeCount()
    val openCount = db.evidenceDao().observeOpenCount()
    val runs = db.runDao().observeAll()
    val reports = db.reportDao().observeAll()

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
        val runId = db.runDao().insert(
            RunEntity(
                name = "Import ${sourceName}",
                createdAt = importedAt,
                evidenceCount = rows.size,
                openNetworkCount = rows.count { it.security.contains("OPEN", ignoreCase = true) },
                hiddenSsidCount = rows.count { it.ssid == "<hidden>" }
            )
        )
        db.reportDao().insertAll(
            listOf(
                ReportEntity(
                    runId = runId,
                    reportType = "summary",
                    title = "Run Summary",
                    body = "Imported ${rows.size} rows from $sourceName.",
                    createdAt = importedAt
                )
            )
        )
        return rows.size
    }
}
