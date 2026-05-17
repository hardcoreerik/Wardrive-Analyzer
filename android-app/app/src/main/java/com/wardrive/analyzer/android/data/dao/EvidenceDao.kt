package com.wardrive.analyzer.android.data.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.wardrive.analyzer.android.data.model.EvidenceEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface EvidenceDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertAll(items: List<EvidenceEntity>)

    @Query("SELECT * FROM evidence ORDER BY seenAt DESC")
    fun observeAll(): Flow<List<EvidenceEntity>>

    @Query("SELECT COUNT(*) FROM evidence")
    fun observeCount(): Flow<Int>

    @Query("SELECT COUNT(*) FROM evidence WHERE security LIKE '%OPEN%'")
    fun observeOpenCount(): Flow<Int>

    @Query("DELETE FROM evidence")
    suspend fun clear()
}
