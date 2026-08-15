package com.wardrive.analyzer.android.ui.map

import androidx.compose.ui.geometry.Offset

enum class MapEntityType {
    WIFI,
    BLE,
    HANDSHAKE,
    GPS
}

enum class MapEntityTypeFilter {
    ALL,
    WIFI,
    BLE,
    HANDSHAKES,
    GPS
}

data class PixelThemeTokens(
    val panelStrokePx: Float = 2f,
    val pixelCornerPx: Float = 4f,
    val glowAlpha: Float = 0.22f
)

data class PixelPanelStyle(
    val denseMode: Boolean = true,
    val showScanlines: Boolean = true
)

data class PixelMapStyle(
    val isoScaleX: Float = 1f,
    val isoScaleY: Float = 0.55f,
    val isoSkew: Float = 0.5f,
    val minZoom: Float = 0.65f,
    val maxZoom: Float = 2.6f
)

data class MapEntityPoint(
    val id: String,
    val type: MapEntityType,
    val latitude: Double,
    val longitude: Double,
    val title: String,
    val subtitle: String,
    val bssid: String?,
    val security: String?,
    val channel: Int?,
    val rssi: Int?,
    val seenAt: Long?,
    val vendor: String? = null
)

data class MapRoutePath(
    val points: List<Offset>,
    val distanceKm: Double
)

data class MapSummaryStats(
    val sessionCount: Int,
    val apCount: Int,
    val bleCount: Int,
    val handshakeCount: Int,
    val gpsFixCount: Int,
    val distanceKm: Double,
    val strongestSignalDbm: Int?
)

data class MapViewport(
    val offsetX: Float = 0f,
    val offsetY: Float = 0f,
    val zoom: Float = 1f
)

data class MapScreenState(
    val hasGeoData: Boolean = false,
    val entities: List<MapEntityPoint> = emptyList(),
    val filteredEntities: List<MapEntityPoint> = emptyList(),
    val route: MapRoutePath = MapRoutePath(emptyList(), 0.0),
    val stats: MapSummaryStats = MapSummaryStats(0, 0, 0, 0, 0, 0.0, null),
    val filter: MapEntityTypeFilter = MapEntityTypeFilter.ALL,
    val selectedEntityId: String? = null,
    val selectedEntity: MapEntityPoint? = null,
    val recentActivity: List<String> = emptyList(),
    val viewport: MapViewport = MapViewport()
)
