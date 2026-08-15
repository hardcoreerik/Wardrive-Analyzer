package com.wardrive.analyzer.android.ui.map

import com.wardrive.analyzer.android.data.model.EvidenceEntity
import com.wardrive.analyzer.android.data.model.MarauderWardriveRecordEntity
import com.wardrive.analyzer.android.data.model.ReportEntity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class MapAggregationTest {

    @Test
    fun projectionNormalizesAndProducesIsoCoordinates() {
        val points = listOf(
            37.0 to -122.0,
            37.1 to -122.1,
            37.2 to -122.2
        )
        val result = MapAggregation.projectToIsometric(points)
        assertEquals(3, result.normalized.size)
        assertEquals(3, result.isoPoints.size)
        assertTrue(result.isoPoints.all { it.x in -0.5f..1.5f && it.y in -0.5f..1.5f })
    }

    @Test
    fun routeDistanceReturnsPositiveValueForDistinctPoints() {
        val km = MapAggregation.routeDistanceKm(
            listOf(
                37.7749 to -122.4194,
                37.7849 to -122.4094
            )
        )
        assertTrue(km > 0.5)
    }

    @Test
    fun filteringAndStatsAreDeterministic() {
        val evidence = listOf(
            EvidenceEntity(
                id = 1,
                sourceName = "a",
                bssid = "AA",
                ssid = "Cafe",
                security = "WPA2",
                channel = 6,
                rssi = -48,
                latitude = 37.7749,
                longitude = -122.4194,
                seenAt = 1000,
                importedAt = 1000,
                importBatch = "b"
            ),
            EvidenceEntity(
                id = 2,
                sourceName = "a",
                bssid = "BB",
                ssid = "Hand",
                security = "WPA2 HANDSHAKE",
                channel = 11,
                rssi = -62,
                latitude = 37.7755,
                longitude = -122.4180,
                seenAt = 1200,
                importedAt = 1000,
                importBatch = "b"
            )
        )
        val wardrive = listOf(
            MarauderWardriveRecordEntity(
                id = 5,
                sourceType = "sd_import",
                sessionId = null,
                importId = "i",
                ssid = "BLE-ish",
                bssid = "CC",
                rssi = -70,
                channel = 1,
                encryption = "ble",
                latitude = 37.776,
                longitude = -122.417,
                accuracy = 2.0,
                timestamp = 1300,
                rawLine = "raw"
            )
        )
        val reports = listOf(
            ReportEntity(id = 1, runId = 1, reportType = "summary", title = "R1", body = "ok", createdAt = 1)
        )
        val allState = MapAggregation.buildState(
            evidence = evidence,
            wardrive = wardrive,
            reports = reports,
            runsCount = 2,
            filter = MapEntityTypeFilter.ALL,
            selectedEntityId = null,
            viewport = MapViewport()
        )
        assertTrue(allState.stats.apCount >= 2)
        assertTrue(allState.stats.handshakeCount >= 1)

        val wifiState = MapAggregation.buildState(
            evidence = evidence,
            wardrive = wardrive,
            reports = reports,
            runsCount = 2,
            filter = MapEntityTypeFilter.WIFI,
            selectedEntityId = null,
            viewport = MapViewport()
        )
        assertTrue(wifiState.filteredEntities.all { it.type == MapEntityType.WIFI })
    }
}
