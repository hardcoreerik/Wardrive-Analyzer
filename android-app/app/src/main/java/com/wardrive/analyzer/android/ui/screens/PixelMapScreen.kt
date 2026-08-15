package com.wardrive.analyzer.android.ui.screens

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.gestures.detectTransformGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.wardrive.analyzer.android.ui.components.PixelChip
import com.wardrive.analyzer.android.ui.components.PixelBlue
import com.wardrive.analyzer.android.ui.components.PixelCyan
import com.wardrive.analyzer.android.ui.components.PixelGreen
import com.wardrive.analyzer.android.ui.components.PixelLegendDot
import com.wardrive.analyzer.android.ui.components.PixelPanel
import com.wardrive.analyzer.android.ui.components.PixelPurple
import com.wardrive.analyzer.android.ui.components.PixelRed
import com.wardrive.analyzer.android.ui.components.PixelStatCard
import com.wardrive.analyzer.android.ui.map.MapAggregation
import com.wardrive.analyzer.android.ui.map.MapEntityPoint
import com.wardrive.analyzer.android.ui.map.MapEntityType
import com.wardrive.analyzer.android.ui.map.MapEntityTypeFilter
import com.wardrive.analyzer.android.ui.map.MapScreenState
import kotlin.math.hypot

@Composable
fun PixelMapScreen(
    modifier: Modifier = Modifier,
    state: MapScreenState,
    onFilterChanged: (MapEntityTypeFilter) -> Unit,
    onSelectEntity: (String?) -> Unit,
    onViewportChanged: (Float, Float) -> Unit,
    onViewportScale: (Float) -> Unit,
    onNavigatePlaceholder: () -> Unit = {},
    onDetailPlaceholder: () -> Unit = {},
    onNotePlaceholder: () -> Unit = {}
) {
    val projected = remember(state.filteredEntities) {
        val coords = state.filteredEntities.map { it.latitude to it.longitude }
        val iso = MapAggregation.projectToIsometric(coords).isoPoints
        state.filteredEntities.zip(iso)
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(Brush.verticalGradient(listOf(Color(0xFF050A15), Color(0xFF03070E))))
            .verticalScroll(rememberScrollState())
            .padding(8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        PixelPanel(title = "Map", accent = PixelCyan) {
            Text("ISOMETRIC SIGNAL GRID", color = PixelCyan, fontWeight = FontWeight.Bold, letterSpacing = 1.sp, fontSize = 15.sp)
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                PixelLegendDot(PixelCyan, "Wi-Fi")
                PixelLegendDot(PixelPurple, "BLE")
                PixelLegendDot(PixelRed, "Handshakes")
                PixelLegendDot(PixelGreen, "GPS")
            }
        }

        PixelPanel(accent = PixelCyan, modifier = Modifier.fillMaxWidth()) {
            Canvas(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(270.dp)
                    .background(Color(0xFF071124))
                    .pointerInput(state.selectedEntityId) {
                        detectTapGestures { tap ->
                            val nearest = projected.minByOrNull { (_, iso) ->
                                val x = (((iso.x - 0.5f) * state.viewport.zoom) + 0.5f) * size.width + state.viewport.offsetX
                                val y = (((iso.y - 0.5f) * state.viewport.zoom) + 0.5f) * size.height + state.viewport.offsetY
                                hypot((tap.x - x).toDouble(), (tap.y - y).toDouble())
                            }
                            if (nearest == null) {
                                onSelectEntity(null)
                            } else {
                                onSelectEntity(nearest.first.id)
                            }
                        }
                    }
                    .pointerInput(Unit) {
                        detectTransformGestures { _, pan, zoom, _ ->
                            onViewportChanged(pan.x, pan.y)
                            onViewportScale(zoom)
                        }
                    }
            ) {
                val gridStep = (size.minDimension / 10f) * state.viewport.zoom
                for (i in -2..12) {
                    val path = Path().apply {
                        moveTo(i * gridStep + state.viewport.offsetX, state.viewport.offsetY)
                        lineTo(i * gridStep - size.width + state.viewport.offsetX, size.height + state.viewport.offsetY)
                    }
                    drawPath(path, Color(0x222A5E93), style = androidx.compose.ui.graphics.drawscope.Stroke(width = 1f))
                }
                for (j in -2..12) {
                    val path = Path().apply {
                        moveTo(j * gridStep + state.viewport.offsetX, state.viewport.offsetY)
                        lineTo(j * gridStep + size.width + state.viewport.offsetX, size.height + state.viewport.offsetY)
                    }
                    drawPath(path, Color(0x161D456E), style = androidx.compose.ui.graphics.drawscope.Stroke(width = 1f))
                }

                if (state.route.points.size > 1) {
                    val routePath = Path().apply {
                        state.route.points.forEachIndexed { idx, point ->
                            val x = (((point.x - 0.5f) * state.viewport.zoom) + 0.5f) * size.width + state.viewport.offsetX
                            val y = (((point.y - 0.5f) * state.viewport.zoom) + 0.5f) * size.height + state.viewport.offsetY
                            if (idx == 0) moveTo(x, y) else lineTo(x, y)
                        }
                    }
                    drawPath(routePath, Color(0xFF22A9FF), style = androidx.compose.ui.graphics.drawscope.Stroke(width = 3.2f))
                }

                projected.take(500).forEach { (entity, iso) ->
                    val x = (((iso.x - 0.5f) * state.viewport.zoom) + 0.5f) * size.width + state.viewport.offsetX
                    val y = (((iso.y - 0.5f) * state.viewport.zoom) + 0.5f) * size.height + state.viewport.offsetY
                    val color = when (entity.type) {
                        MapEntityType.WIFI -> PixelCyan
                        MapEntityType.BLE -> PixelPurple
                        MapEntityType.HANDSHAKE -> PixelRed
                        MapEntityType.GPS -> PixelGreen
                    }
                    val selected = entity.id == state.selectedEntityId
                    drawPixelSprite(type = entity.type, center = Offset(x, y), color = color, scale = if (selected) 2.1f else 1.7f)
                }
            }
        }

        LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            items(MapEntityTypeFilter.entries) { filter ->
                PixelChip(text = filterLabel(filter), selected = state.filter == filter, onClick = { onFilterChanged(filter) })
            }
        }

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
            PixelStatCard("Sessions", state.stats.sessionCount.toString(), "Total", PixelCyan, Modifier.weight(1f))
            PixelStatCard("Distance", String.format("%.2f", state.stats.distanceKm), "KM", PixelBlue, Modifier.weight(1f))
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
            PixelStatCard("APs", state.stats.apCount.toString(), "Wi-Fi", PixelCyan, Modifier.weight(1f))
            PixelStatCard("Handshakes", state.stats.handshakeCount.toString(), "Captured", PixelRed, Modifier.weight(1f))
        }

        SelectedEntityPanel(
            entity = state.selectedEntity,
            onNavigatePlaceholder = onNavigatePlaceholder,
            onDetailPlaceholder = onDetailPlaceholder,
            onNotePlaceholder = onNotePlaceholder
        )
    }
}

@Composable
private fun SelectedEntityPanel(
    entity: MapEntityPoint?,
    onNavigatePlaceholder: () -> Unit,
    onDetailPlaceholder: () -> Unit,
    onNotePlaceholder: () -> Unit
) {
    PixelPanel(title = "Selected", accent = PixelCyan, modifier = Modifier.fillMaxWidth()) {
        if (entity == null) {
            Text("Tap a marker to inspect SSID/BSSID/signal and telemetry.", color = Color(0xFF98B7DB))
            return@PixelPanel
        }
        Text(entity.title, color = Color.White, fontWeight = FontWeight.Bold, fontSize = 22.sp)
        Text(entity.subtitle, color = Color(0xFF8FB2D8))
        Text("BSSID: ${entity.bssid ?: "N/A"}", color = Color(0xFFB4CBE7))
        Text("Security: ${entity.security ?: "N/A"}", color = Color(0xFFB4CBE7))
        Text("CH: ${entity.channel ?: "-"}   RSSI: ${entity.rssi ?: 0} dBm", color = Color(0xFFB4CBE7))

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
            PixelChip("DETAILS", selected = false, onClick = onDetailPlaceholder, modifier = Modifier.weight(1f))
            PixelChip("ADD NOTE", selected = false, onClick = onNotePlaceholder, modifier = Modifier.weight(1f))
            PixelChip("NAVIGATE", selected = true, onClick = onNavigatePlaceholder, modifier = Modifier.weight(1f))
        }
    }
}

private fun DrawScope.drawPixelSprite(
    type: MapEntityType,
    center: Offset,
    color: Color,
    scale: Float
) {
    val px = scale
    val pattern = when (type) {
        MapEntityType.WIFI -> arrayOf(
            "0011100",
            "0100010",
            "1000001",
            "0011100",
            "0001000",
            "0000000",
            "0001000"
        )
        MapEntityType.BLE -> arrayOf(
            "0001000",
            "0011000",
            "0101000",
            "1111110",
            "0101000",
            "0011000",
            "0001000"
        )
        MapEntityType.HANDSHAKE -> arrayOf(
            "1100011",
            "1100011",
            "0111110",
            "0011100",
            "0111110",
            "1100011",
            "1100011"
        )
        MapEntityType.GPS -> arrayOf(
            "0011100",
            "0100010",
            "1000001",
            "1001001",
            "1000001",
            "0100010",
            "0011100"
        )
    }
    val half = (pattern.size * px) / 2f
    for (row in pattern.indices) {
        for (col in pattern[row].indices) {
            if (pattern[row][col] != '1') continue
            drawRect(
                color = color,
                topLeft = Offset(center.x - half + (col * px), center.y - half + (row * px)),
                size = androidx.compose.ui.geometry.Size(px, px)
            )
        }
    }
}

private fun filterLabel(filter: MapEntityTypeFilter): String {
    return when (filter) {
        MapEntityTypeFilter.ALL -> "ALL"
        MapEntityTypeFilter.WIFI -> "WI-FI"
        MapEntityTypeFilter.BLE -> "BLE"
        MapEntityTypeFilter.HANDSHAKES -> "HANDSHAKES"
        MapEntityTypeFilter.GPS -> "GPS"
    }
}
