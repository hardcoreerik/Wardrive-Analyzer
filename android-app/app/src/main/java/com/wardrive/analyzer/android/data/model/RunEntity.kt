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
    val hiddenSsidCount: Int
)
