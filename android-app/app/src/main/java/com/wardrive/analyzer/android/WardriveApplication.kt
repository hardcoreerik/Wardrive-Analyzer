package com.wardrive.analyzer.android

import android.app.Application
import androidx.room.Room
import com.wardrive.analyzer.android.data.db.WardriveDatabase
import com.wardrive.analyzer.android.data.repo.WardriveRepository

class WardriveApplication : Application() {
    lateinit var repository: WardriveRepository
        private set

    override fun onCreate() {
        super.onCreate()
        val db = Room.databaseBuilder(
            applicationContext,
            WardriveDatabase::class.java,
            "wardrive_android.db"
        ).fallbackToDestructiveMigration().build()
        repository = WardriveRepository(db)
    }
}
