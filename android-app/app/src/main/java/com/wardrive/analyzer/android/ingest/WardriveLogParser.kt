package com.wardrive.analyzer.android.ingest

import java.io.BufferedReader

class WardriveLogParser {
    fun parse(reader: BufferedReader): List<ParsedEvidence> {
        val out = mutableListOf<ParsedEvidence>()
        reader.useLines { lines ->
            lines.forEach { raw ->
                val line = raw.trim()
                if (line.isBlank() || line.startsWith("WigleWifi") || line.startsWith("#")) return@forEach
                val cols = line.split(',')
                if (cols.size < 8) return@forEach
                val bssid = cols.getOrNull(0)?.trim().orEmpty()
                val ssid = cols.getOrNull(1)?.trim().orEmpty()
                val security = cols.getOrNull(2)?.trim().orEmpty()
                val channel = cols.getOrNull(4)?.trim()?.toIntOrNull()
                val rssi = cols.getOrNull(5)?.trim()?.toIntOrNull()
                val lat = cols.getOrNull(6)?.trim()?.toDoubleOrNull()
                val lon = cols.getOrNull(7)?.trim()?.toDoubleOrNull()
                if (bssid.isBlank()) return@forEach
                out += ParsedEvidence(
                    bssid = bssid,
                    ssid = if (ssid.isBlank()) "<hidden>" else ssid,
                    security = security,
                    channel = channel,
                    rssi = rssi,
                    latitude = lat,
                    longitude = lon,
                    seenAt = System.currentTimeMillis()
                )
            }
        }
        return out
    }
}
