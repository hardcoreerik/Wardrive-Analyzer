package com.wardrive.analyzer.android

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.lifecycle.viewmodel.compose.viewModel
import com.wardrive.analyzer.android.ui.theme.WardriveTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        applyDropboxConfigFromIntent(intent)
        enableEdgeToEdge()
        val app = application as WardriveApplication
        setContent {
            WardriveTheme {
                val vm: WardriveViewModel = viewModel(factory = WardriveViewModel.factory(app))
                WardriveApp(vm)
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        applyDropboxConfigFromIntent(intent)
    }

    private fun applyDropboxConfigFromIntent(intent: Intent?) {
        if (intent == null) return
        val apply = intent.getBooleanExtra("dropbox_apply", false)
        if (!apply) return
        val token = intent.getStringExtra("dropbox_token")?.trim().orEmpty()
        val folder = intent.getStringExtra("dropbox_folder")?.trim().orEmpty()
        val zipName = intent.getStringExtra("dropbox_zip_name")?.trim().orEmpty()
        if (token.isBlank()) return
        val normalizedFolder = if (folder.isBlank()) "/WardriveAnalyzerProjects" else folder
        getSharedPreferences("dropbox_sync", MODE_PRIVATE)
            .edit()
            .putString("token", token)
            .putString("folder", normalizedFolder)
            .putString("zip_name", zipName)
            .apply()
    }
}
