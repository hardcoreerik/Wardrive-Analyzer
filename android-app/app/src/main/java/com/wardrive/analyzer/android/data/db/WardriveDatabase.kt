package com.wardrive.analyzer.android.data.db

import androidx.room.Database
import androidx.room.RoomDatabase
import com.wardrive.analyzer.android.data.dao.EvidenceDao
import com.wardrive.analyzer.android.data.dao.MarauderDao
import com.wardrive.analyzer.android.data.dao.ReportDao
import com.wardrive.analyzer.android.data.dao.RunDao
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

@Database(
    entities = [
        EvidenceEntity::class,
        RunEntity::class,
        ReportEntity::class,
        MarauderLiveSessionEntity::class,
        MarauderSerialLogEntity::class,
        MarauderApRecordEntity::class,
        MarauderStationRecordEntity::class,
        MarauderWardriveRecordEntity::class,
        MarauderImportedFileEntity::class,
        ProjectProfileEntity::class,
        SyncRecordEntity::class
    ],
    version = 6,
    exportSchema = false
)
abstract class WardriveDatabase : RoomDatabase() {
    abstract fun evidenceDao(): EvidenceDao
    abstract fun runDao(): RunDao
    abstract fun reportDao(): ReportDao
    abstract fun marauderDao(): MarauderDao
}
