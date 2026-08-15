package com.wardrive.analyzer.android.data.model

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "reports")
data class ReportEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val runId: Long,
    val reportType: String,
    val title: String,
    val body: String,
    val createdAt: Long
)
