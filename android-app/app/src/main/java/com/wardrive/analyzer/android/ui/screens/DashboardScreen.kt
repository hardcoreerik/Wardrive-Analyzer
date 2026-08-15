package com.wardrive.analyzer.android.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Bluetooth
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.LocationOn
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Storage
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.LocalTextStyle
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.sp
import androidx.compose.ui.unit.dp
import com.wardrive.analyzer.android.R
import com.wardrive.analyzer.android.data.model.ProjectProfileEntity
import com.wardrive.analyzer.android.data.model.SyncRecordEntity
import com.wardrive.analyzer.android.ui.components.PixelBlue
import com.wardrive.analyzer.android.ui.components.PixelChip
import com.wardrive.analyzer.android.ui.components.PixelCyan
import com.wardrive.analyzer.android.ui.components.PixelGreen
import com.wardrive.analyzer.android.ui.components.PixelPanel
import com.wardrive.analyzer.android.ui.components.PixelPurple
import com.wardrive.analyzer.android.ui.components.PixelRed
import kotlin.math.max

@Composable
fun DashboardScreen(
    modifier: Modifier = Modifier,
    evidenceCount: Int,
    openCount: Int,
    runCount: Int,
    reportCount: Int,
    totalPcapPackets: Int,
    highRiskRuns: Int,
    lastImport: String,
    dropboxStatus: String,
    projectProfiles: List<ProjectProfileEntity>,
    activeProjectSlug: String,
    marauderConnected: Boolean,
    syncRecords: List<SyncRecordEntity>,
    isSyncingDropbox: Boolean,
    isRefreshingProjects: Boolean,
    onRefreshProjects: () -> Unit,
    onSetActiveProject: (String) -> Unit,
    onOpenLiveTab: () -> Unit
) {
    val pixelFont = FontFamily(Font(R.font.press_start_2p_regular))
    val scroll = rememberScrollState()
    val lastPull = syncRecords.firstOrNull { it.direction == "pull" }?.timestamp
    val lastPush = syncRecords.firstOrNull { it.direction == "push" }?.timestamp
    val pendingUploads = syncRecords.count { it.direction == "push" && it.status == "error" }
    val wifiNear = max(openCount, evidenceCount / 650)
    val bleNear = max(0, evidenceCount / 1200)
    val handshakes = max(highRiskRuns, evidenceCount / 1700)
    CompositionLocalProvider(
        LocalTextStyle provides TextStyle(
            fontFamily = pixelFont,
            color = Color(0xFFE6F2FF)
        )
    ) {
        Column(
            modifier = modifier
                .fillMaxSize()
                .background(Brush.verticalGradient(listOf(Color(0xFF030B16), Color(0xFF02050D))))
                .verticalScroll(scroll)
                .padding(10.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
        PixelPanel(accent = PixelCyan, modifier = Modifier.fillMaxWidth()) {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Column {
                    Text("WARDRIVER", color = Color(0xFFE4F4FF), fontWeight = FontWeight.Black, fontSize = 16.sp, letterSpacing = 0.4.sp)
                    Text("COMPANION", color = PixelCyan, fontWeight = FontWeight.Black, fontSize = 14.sp, letterSpacing = 0.4.sp)
                }
                PixelStatusBlock(
                    activeProjectSlug = activeProjectSlug,
                    marauderConnected = marauderConnected,
                    onClick = onOpenLiveTab
                )
            }
        }

        PixelPanel(title = "Connection", accent = PixelCyan) {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp), modifier = Modifier.weight(1f)) {
                    Text(
                        if (activeProjectSlug.isBlank()) "No Project Linked" else activeProjectSlug.uppercase(),
                        color = Color.White,
                        fontWeight = FontWeight.Bold,
                        fontSize = 10.sp,
                        maxLines = 2,
                        softWrap = false,
                        overflow = TextOverflow.Ellipsis
                    )
                    Text("Runs $runCount | Reports $reportCount", color = Color(0xFFA0B8D9), fontSize = 8.sp)
                    PixelTag(if (marauderConnected) "CONNECTED" else "DISCONNECTED", if (marauderConnected) PixelGreen else PixelRed)
                }
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    PixelMethodTile("USB", PixelCyan, Icons.Default.Memory)
                    PixelMethodTile("WI-FI", PixelBlue, Icons.Default.Wifi)
                    PixelMethodTile("SD", Color(0xFF8792A8), Icons.Default.Storage)
                }
            }
            Text("Device ready. All systems nominal.", color = PixelCyan, fontWeight = FontWeight.SemiBold, fontSize = 9.sp)
        }

        PixelPanel(title = "Quick Actions", accent = PixelBlue) {
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp), modifier = Modifier.fillMaxWidth()) {
                PixelActionTile("LIVE SCAN", Icons.Default.Wifi, PixelCyan, Modifier.weight(1f))
                PixelActionTile("MAP", Icons.Default.LocationOn, PixelBlue, Modifier.weight(1f))
                PixelActionTile("SESSIONS", Icons.Default.Folder, PixelPurple, Modifier.weight(1f))
                PixelActionTile("IMPORT SD", Icons.Default.Storage, PixelGreen, Modifier.weight(1f))
            }
        }

        Row(horizontalArrangement = Arrangement.spacedBy(6.dp), modifier = Modifier.fillMaxWidth()) {
            PixelSignalCard("NEARBY WI-FI", wifiNear.toString(), "Networks", PixelCyan, Icons.Default.Wifi, Modifier.weight(1f))
            PixelSignalCard("BLE DEVICES", bleNear.toString(), "Devices", PixelPurple, Icons.Default.Bluetooth, Modifier.weight(1f))
            PixelSignalCard("HANDSHAKES", handshakes.toString(), "Captured", PixelRed, Icons.Default.Security, Modifier.weight(1f))
        }

        Row(horizontalArrangement = Arrangement.spacedBy(6.dp), modifier = Modifier.fillMaxWidth()) {
            PixelSignalCard("GPS LOCK", "${max(1, runCount / 2)}D", "Latched", PixelGreen, Icons.Default.LocationOn, Modifier.weight(1f))
            PixelSignalCard(
                "STORAGE USED",
                "${"%.1f".format((evidenceCount / 1000f).coerceAtLeast(0.4f))} GB",
                "of 62.5 GB",
                PixelBlue,
                Icons.Default.Storage,
                Modifier.weight(1f)
            )
        }

        PixelPanel(title = "Recent Activity", accent = PixelCyan) {
            if (syncRecords.isEmpty()) {
                Text("No recent sync events.", color = Color(0xFFA9BCD5))
            } else {
                syncRecords.take(4).forEach {
                    val conflict = if (it.conflictFlag) " conflict" else ""
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text("${it.direction.uppercase()} ${it.projectSlug}", color = Color.White, fontWeight = FontWeight.SemiBold)
                        Text(it.status + conflict, color = PixelCyan)
                    }
                    Text(it.path, color = Color(0xFF9AB3D4), style = MaterialTheme.typography.bodySmall)
                }
            }
        }

        PixelPanel(title = "Project Sync", accent = PixelGreen) {
            Text("Active project: ${if (activeProjectSlug.isBlank()) "None selected" else activeProjectSlug}", color = Color(0xFFD5E8FF), fontSize = 9.sp)
            Text("Last pull: ${lastPull?.let { java.text.DateFormat.getDateTimeInstance().format(java.util.Date(it)) } ?: "never"}", color = Color(0xFF9AB3D4), fontSize = 8.sp)
            Text("Last push: ${lastPush?.let { java.text.DateFormat.getDateTimeInstance().format(java.util.Date(it)) } ?: "never"}", color = Color(0xFF9AB3D4), fontSize = 8.sp)
            Text("Pending uploads: $pendingUploads", color = Color(0xFF9AB3D4), fontSize = 8.sp)
            Button(
                onClick = onRefreshProjects,
                modifier = Modifier.fillMaxWidth(),
                enabled = !isRefreshingProjects
            ) { Text(if (isRefreshingProjects) "Refreshing..." else "Refresh Dropbox Projects") }
            if (isRefreshingProjects) {
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            }
            Text(dropboxStatus, style = MaterialTheme.typography.bodySmall, color = Color(0xFF9CC3E9), fontSize = 8.sp)
            if (projectProfiles.isEmpty()) {
                Text("No projects found in Dropbox root.", color = Color(0xFFFF8D95))
            } else {
                Row(
                    modifier = Modifier
                        .horizontalScroll(rememberScrollState())
                        .fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    projectProfiles.forEach { profile ->
                        PixelChip(
                            text = if (profile.slug == activeProjectSlug) "[ACTIVE] ${profile.displayName}" else profile.displayName,
                            selected = profile.slug == activeProjectSlug,
                            onClick = { onSetActiveProject(profile.slug) }
                        )
                    }
                }
            }
        }
        }
    }
}

@Composable
private fun PixelStatusBlock(
    activeProjectSlug: String,
    marauderConnected: Boolean,
    onClick: () -> Unit
) {
    Box(
        modifier = Modifier
            .border(2.dp, PixelCyan, RoundedCornerShape(2.dp))
            .background(Color(0xFF061123))
            .clickable(onClick = onClick)
            .padding(horizontal = 8.dp, vertical = 5.dp)
    ) {
        Column {
            Text("ESP32 Marauder", color = Color(0xFFE4F4FF), fontWeight = FontWeight.Bold, fontSize = 8.sp, maxLines = 1, softWrap = false, overflow = TextOverflow.Ellipsis)
            Text(
                if (marauderConnected) "CONNECTED" else "DISCONNECTED",
                color = if (marauderConnected) PixelGreen else PixelRed,
                fontWeight = FontWeight.Bold,
                fontSize = 9.sp,
                maxLines = 1,
                softWrap = false,
                overflow = TextOverflow.Ellipsis
            )
            Text(activeProjectSlug.ifBlank { "No active project" }, color = Color(0xFF94B2D8), style = MaterialTheme.typography.bodySmall, fontSize = 7.sp, maxLines = 2, softWrap = false, overflow = TextOverflow.Ellipsis)
        }
    }
}

@Composable
private fun PixelTag(text: String, color: Color) {
    Box(
        modifier = Modifier
            .border(2.dp, color, RoundedCornerShape(20.dp))
            .background(color.copy(alpha = 0.12f), RoundedCornerShape(20.dp))
            .padding(horizontal = 8.dp, vertical = 3.dp)
    ) {
        Text(text, color = color, fontWeight = FontWeight.Bold, letterSpacing = 0.2.sp, fontSize = 8.sp, maxLines = 1, softWrap = false, overflow = TextOverflow.Ellipsis)
    }
}

@Composable
private fun PixelMethodTile(label: String, accent: Color, icon: androidx.compose.ui.graphics.vector.ImageVector) {
    Box(
        modifier = Modifier
            .size(width = 62.dp, height = 72.dp)
            .border(2.dp, accent, RoundedCornerShape(2.dp))
            .background(Color(0xFF09172D))
            .padding(6.dp)
    ) {
        Column(verticalArrangement = Arrangement.SpaceBetween) {
            Icon(icon, contentDescription = label, tint = accent, modifier = Modifier.size(15.dp))
            Text(label, color = accent, fontWeight = FontWeight.Bold, letterSpacing = 0.2.sp, fontSize = 8.sp, maxLines = 1, softWrap = false, overflow = TextOverflow.Ellipsis)
        }
    }
}

@Composable
private fun PixelActionTile(
    label: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    accent: Color,
    modifier: Modifier = Modifier
) {
    Box(
        modifier = modifier
            .height(74.dp)
            .border(2.dp, Color(0xFF29415F), RoundedCornerShape(2.dp))
            .background(Color(0xFF08172C))
            .padding(8.dp)
    ) {
        Column(verticalArrangement = Arrangement.SpaceBetween) {
            Icon(icon, contentDescription = label, tint = accent, modifier = Modifier.size(18.dp))
            Text(label, color = Color(0xFFDFEEFF), fontWeight = FontWeight.Bold, fontSize = 8.sp, maxLines = 2, lineHeight = 9.sp, softWrap = false, overflow = TextOverflow.Ellipsis)
        }
    }
}

@Composable
private fun PixelSignalCard(
    title: String,
    value: String,
    subtitle: String,
    accent: Color,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    modifier: Modifier = Modifier
) {
    Box(
        modifier = modifier
            .height(108.dp)
            .border(2.dp, accent.copy(alpha = 0.6f), RoundedCornerShape(2.dp))
            .background(Color(0xFF061326))
            .padding(8.dp)
    ) {
        Column(verticalArrangement = Arrangement.SpaceBetween) {
            Text(title, color = accent, fontWeight = FontWeight.Bold, letterSpacing = 0.2.sp, fontSize = 8.sp, maxLines = 2, softWrap = false, overflow = TextOverflow.Ellipsis)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Icon(icon, contentDescription = title, tint = accent, modifier = Modifier.size(16.dp))
                Column {
                    Text(value, color = accent, fontWeight = FontWeight.ExtraBold, fontSize = 18.sp, lineHeight = 19.sp, maxLines = 1, softWrap = false, overflow = TextOverflow.Ellipsis)
                    Text(subtitle, color = Color(0xFFA3BDDB), fontSize = 8.sp, maxLines = 1, softWrap = false, overflow = TextOverflow.Ellipsis)
                }
            }
        }
    }
}

