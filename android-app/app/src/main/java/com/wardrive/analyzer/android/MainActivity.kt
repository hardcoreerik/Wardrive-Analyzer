package com.wardrive.analyzer.android

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.lifecycle.viewmodel.compose.viewModel
import com.wardrive.analyzer.android.ui.theme.WardriveTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        val app = application as WardriveApplication
        setContent {
            WardriveTheme {
                val vm: WardriveViewModel = viewModel(factory = WardriveViewModel.factory(app))
                WardriveApp(vm)
            }
        }
    }
}
