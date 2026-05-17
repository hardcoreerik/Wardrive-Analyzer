package com.wardrive.analyzer.android.data.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.wardrive.analyzer.android.data.model.RunEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface RunDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(run: RunEntity): Long

    @Query("SELECT * FROM runs ORDER BY createdAt DESC")
    fun observeAll(): Flow<List<RunEntity>>
}
