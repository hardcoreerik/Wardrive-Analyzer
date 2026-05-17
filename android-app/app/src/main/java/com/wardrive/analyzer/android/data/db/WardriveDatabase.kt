package com.wardrive.analyzer.android.data.db

import androidx.room.Database
import androidx.room.RoomDatabase
import com.wardrive.analyzer.android.data.dao.EvidenceDao
import com.wardrive.analyzer.android.data.dao.ReportDao
import com.wardrive.analyzer.android.data.dao.RunDao
import com.wardrive.analyzer.android.data.model.EvidenceEntity
import com.wardrive.analyzer.android.data.model.ReportEntity
import com.wardrive.analyzer.android.data.model.RunEntity

@Database(
    entities = [EvidenceEntity::class, RunEntity::class, ReportEntity::class],
    version = 1,
    exportSchema = false
)
abstract class WardriveDatabase : RoomDatabase() {
    abstract fun evidenceDao(): EvidenceDao
    abstract fun runDao(): RunDao
    abstract fun reportDao(): ReportDao
}
