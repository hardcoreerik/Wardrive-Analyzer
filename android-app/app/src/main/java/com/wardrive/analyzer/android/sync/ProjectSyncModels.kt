package com.wardrive.analyzer.android.sync

data class ProjectProfile(
    val slug: String,
    val displayName: String,
    val dropboxPath: String,
    val isActive: Boolean = false,
    val lastSyncAt: Long? = null
)

data class SyncRecord(
    val projectSlug: String,
    val direction: String,
    val path: String,
    val status: String,
    val timestamp: Long,
    val conflictFlag: Boolean = false,
    val message: String = ""
)

data class PullResult(
    val projectSlug: String,
    val filesDownloaded: Int,
    val conflicts: Int,
    val localProjectDir: String
)

