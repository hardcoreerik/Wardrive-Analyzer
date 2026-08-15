package com.wardrive.analyzer.android.data.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import com.wardrive.analyzer.android.data.model.MarauderApRecordEntity
import com.wardrive.analyzer.android.data.model.MarauderImportedFileEntity
import com.wardrive.analyzer.android.data.model.MarauderLiveSessionEntity
import com.wardrive.analyzer.android.data.model.MarauderSerialLogEntity
import com.wardrive.analyzer.android.data.model.MarauderStationRecordEntity
import com.wardrive.analyzer.android.data.model.MarauderWardriveRecordEntity
import com.wardrive.analyzer.android.data.model.ProjectProfileEntity
import com.wardrive.analyzer.android.data.model.SyncRecordEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface MarauderDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertSession(session: MarauderLiveSessionEntity)

    @Update
    suspend fun updateSession(session: MarauderLiveSessionEntity)

    @Query("SELECT * FROM marauder_sessions WHERE sessionId = :sessionId LIMIT 1")
    suspend fun getSession(sessionId: String): MarauderLiveSessionEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertSerialLog(log: MarauderSerialLogEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertAp(record: MarauderApRecordEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertStation(record: MarauderStationRecordEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertWardriveRecord(record: MarauderWardriveRecordEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertWardriveRecords(records: List<MarauderWardriveRecordEntity>)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertImportedFile(file: MarauderImportedFileEntity)

    @Query("SELECT * FROM marauder_imported_files ORDER BY importedAt DESC")
    fun observeImportedFiles(): Flow<List<MarauderImportedFileEntity>>

    @Query("SELECT * FROM marauder_ap_records ORDER BY lastSeen DESC LIMIT 300")
    fun observeApRecords(): Flow<List<MarauderApRecordEntity>>

    @Query("SELECT * FROM marauder_ap_records ORDER BY lastSeen DESC")
    suspend fun getApRecords(): List<MarauderApRecordEntity>

    @Query("SELECT * FROM marauder_wardrive_records ORDER BY COALESCE(timestamp, 0) DESC, id DESC LIMIT 500")
    fun observeWardriveRecords(): Flow<List<MarauderWardriveRecordEntity>>

    @Query("SELECT * FROM marauder_wardrive_records ORDER BY COALESCE(timestamp, 0) DESC, id DESC")
    suspend fun getWardriveRecords(): List<MarauderWardriveRecordEntity>

    @Query("SELECT rawLine FROM marauder_serial_logs WHERE sessionId = :sessionId ORDER BY id ASC")
    suspend fun getRawLogLines(sessionId: String): List<String>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertProjects(projects: List<ProjectProfileEntity>)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertProject(project: ProjectProfileEntity)

    @Query("UPDATE project_profiles SET isActive = CASE WHEN slug = :slug THEN 1 ELSE 0 END")
    suspend fun setActiveProject(slug: String)

    @Query("SELECT * FROM project_profiles ORDER BY displayName ASC")
    fun observeProjects(): Flow<List<ProjectProfileEntity>>

    @Query("SELECT * FROM project_profiles ORDER BY displayName ASC")
    suspend fun getProjects(): List<ProjectProfileEntity>

    @Query("SELECT * FROM project_profiles WHERE isActive = 1 LIMIT 1")
    suspend fun getActiveProject(): ProjectProfileEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertSyncRecord(record: SyncRecordEntity)

    @Query("SELECT * FROM sync_records ORDER BY timestamp DESC LIMIT 120")
    fun observeSyncRecords(): Flow<List<SyncRecordEntity>>
}
