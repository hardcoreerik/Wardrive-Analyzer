package com.wardrive.analyzer.android

import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.wardrive.analyzer.android.data.model.EvidenceEntity
import com.wardrive.analyzer.android.data.model.ReportEntity
import com.wardrive.analyzer.android.data.model.RunEntity
import com.wardrive.analyzer.android.data.repo.WardriveRepository
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.launch
import java.io.BufferedReader
import java.io.InputStreamReader

class WardriveViewModel(
    private val app: WardriveApplication
) : ViewModel() {
    private val repo: WardriveRepository = app.repository

    val evidence: Flow<List<EvidenceEntity>> = repo.evidence
    val runs: Flow<List<RunEntity>> = repo.runs
    val reports: Flow<List<ReportEntity>> = repo.reports
    val evidenceCount = repo.evidenceCount
    val openCount = repo.openCount

    fun importUri(uri: Uri) {
        viewModelScope.launch {
            val resolver = app.contentResolver
            resolver.openInputStream(uri)?.use { stream ->
                BufferedReader(InputStreamReader(stream)).use { reader ->
                    val fileName = uri.lastPathSegment ?: "import.csv"
                    repo.importLog(fileName, reader)
                }
            }
        }
    }

    companion object {
        fun factory(app: WardriveApplication): ViewModelProvider.Factory =
            object : ViewModelProvider.Factory {
                override fun <T : ViewModel> create(modelClass: Class<T>): T {
                    @Suppress("UNCHECKED_CAST")
                    return WardriveViewModel(app) as T
                }
            }
    }
}
