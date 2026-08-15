package com.wardrive.analyzer.android.data.model

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "marauder_sessions")
data class MarauderLiveSessionEntity(
    @PrimaryKey val sessionId: String,
    val startedAt: Long,
    val endedAt: Long?,
    val deviceName: String?,
    val vendorId: Int?,
    val productId: Int?,
    val baudRate: Int,
    val status: String,
    val savedLogPath: String?
)

@Entity(tableName = "marauder_serial_logs")
data class MarauderSerialLogEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val sessionId: String,
    val rawLine: String,
    val seenAt: Long
)

@Entity(tableName = "marauder_ap_records")
data class MarauderApRecordEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val sourceType: String,
    val sessionId: String?,
    val importId: String?,
    val ssid: String,
    val bssid: String,
    val channel: Int?,
    val rssi: Int?,
    val encryption: String?,
    val rawLine: String,
    val firstSeen: Long,
    val lastSeen: Long
)

@Entity(tableName = "marauder_station_records")
data class MarauderStationRecordEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val sourceType: String,
    val sessionId: String?,
    val importId: String?,
    val mac: String,
    val associatedBssid: String?,
    val rssi: Int?,
    val channel: Int?,
    val rawLine: String,
    val firstSeen: Long,
    val lastSeen: Long
)

@Entity(tableName = "marauder_wardrive_records")
data class MarauderWardriveRecordEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val sourceType: String,
    val sessionId: String?,
    val importId: String?,
    val ssid: String?,
    val bssid: String?,
    val rssi: Int?,
    val channel: Int?,
    val encryption: String?,
    val latitude: Double?,
    val longitude: Double?,
    val accuracy: Double?,
    val timestamp: Long?,
    val rawLine: String
)

@Entity(tableName = "marauder_imported_files")
data class MarauderImportedFileEntity(
    @PrimaryKey val importId: String,
    val originalName: String,
    val storedPath: String,
    val sizeBytes: Long,
    val sha256: String,
    val importedAt: Long,
    val fileType: String,
    val parsedRecordCount: Int
)

@Entity(tableName = "project_profiles")
data class ProjectProfileEntity(
    @PrimaryKey val slug: String,
    val displayName: String,
    val dropboxPath: String,
    val isActive: Boolean,
    val lastSyncAt: Long?
)

@Entity(tableName = "sync_records")
data class SyncRecordEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val projectSlug: String,
    val direction: String,
    val path: String,
    val status: String,
    val timestamp: Long,
    val conflictFlag: Boolean,
    val message: String
)
