package com.wardrive.analyzer.android.data.model

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "evidence")
data class EvidenceEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val sourceName: String,
    val bssid: String,
    val ssid: String,
    val security: String,
    val channel: Int?,
    val rssi: Int?,
    val latitude: Double?,
    val longitude: Double?,
    val seenAt: Long,
    val importedAt: Long,
    val importBatch: String
)
