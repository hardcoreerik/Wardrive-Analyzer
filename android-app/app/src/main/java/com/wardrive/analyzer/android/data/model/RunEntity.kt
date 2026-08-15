package com.wardrive.analyzer.android.data.model

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "runs")
data class RunEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val name: String,
    val createdAt: Long,
    val evidenceCount: Int,
    val openNetworkCount: Int,
    val hiddenSsidCount: Int,
    val pcapPacketCount: Int = 0,
    val pcapEapolCount: Int = 0,
    val pcapBytes: Long = 0,
    val pcapApCount: Int = 0,
    val pcapStationCount: Int = 0,
    val handshakeConfidence: String = "NONE",
    val riskScore: Int = 0
)
