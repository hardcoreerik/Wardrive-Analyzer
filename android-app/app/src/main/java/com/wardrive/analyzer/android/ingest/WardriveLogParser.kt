package com.wardrive.analyzer.android.ingest

import java.io.BufferedReader
import java.util.Locale

class WardriveLogParser {
    fun parse(reader: BufferedReader): List<ParsedEvidence> {
        val out = mutableListOf<ParsedEvidence>()
        val rows = reader.readLines()
        if (rows.isEmpty()) return out

        val firstDataLine = rows.firstOrNull { it.trim().isNotBlank() && !it.trim().startsWith("#") } ?: return out
        if (firstDataLine.startsWith("WigleWifi", ignoreCase = true)) {
            rows.forEach { raw ->
                parseLegacyRow(raw)?.let(out::add)
            }
            return out
        }
        val headerCells = parseCsvLine(firstDataLine).map { it.trim() }
        val headerIdx = headerCells.withIndex().associate { it.value.lowercase(Locale.US) to it.index }

        if (isWardriveMasterHeader(headerIdx)) {
            rows.drop(1).forEach { raw ->
                parseWardriveMasterRow(raw, headerIdx)?.let(out::add)
            }
            return out
        }

        if (isGenericEvidenceHeader(headerIdx)) {
            rows.drop(1).forEach { raw ->
                parseGenericHeaderRow(raw, headerIdx)?.let(out::add)
            }
            return out
        }

        rows.forEach { raw ->
            parseLegacyRow(raw)?.let(out::add)
        }
        return out
    }

    private fun parseLegacyRow(raw: String): ParsedEvidence? {
        val line = raw.trim()
        if (line.isBlank() || line.startsWith("WigleWifi") || line.startsWith("#")) return null
        val cols = parseCsvLine(line)
        if (cols.size < 8) return null
        val bssid = cols.getOrNull(0)?.trim().orEmpty()
        val ssid = cols.getOrNull(1)?.trim().orEmpty()
        val security = cols.getOrNull(2)?.trim().orEmpty()
        val channel = cols.getOrNull(4)?.trim()?.toIntOrNull()
        val rssi = cols.getOrNull(5)?.trim()?.toIntOrNull()
        val lat = cols.getOrNull(6)?.trim()?.toDoubleOrNull()
        val lon = cols.getOrNull(7)?.trim()?.toDoubleOrNull()
        if (bssid.isBlank()) return null
        return ParsedEvidence(
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

    private fun parseWardriveMasterRow(raw: String, idx: Map<String, Int>): ParsedEvidence? {
        val line = raw.trim()
        if (line.isBlank() || line.startsWith("#")) return null
        val cols = parseCsvLine(line)
        val bssid = cols.valueOf(idx, "mac")
        if (bssid.isBlank()) return null
        val ssid = cols.valueOf(idx, "topssid")
            .takeUnless { it.equals("no data", ignoreCase = true) || it.isBlank() }
            ?: "<hidden>"
        val security = cols.valueOf(idx, "authmode")
        val channel = cols.valueOf(idx, "channel").toIntOrNull()
        val rssi = cols.valueOf(idx, "bestrssi").toIntOrNull()
        val lat = cols.valueOf(idx, "centroidlat").toDoubleOrNull()
        val lon = cols.valueOf(idx, "centroidlon").toDoubleOrNull()
        return ParsedEvidence(
            bssid = bssid,
            ssid = ssid,
            security = security,
            channel = channel,
            rssi = rssi,
            latitude = lat,
            longitude = lon,
            seenAt = System.currentTimeMillis()
        )
    }

    private fun parseGenericHeaderRow(raw: String, idx: Map<String, Int>): ParsedEvidence? {
        val line = raw.trim()
        if (line.isBlank() || line.startsWith("#")) return null
        val cols = parseCsvLine(line)
        val bssid = cols.valueOf(idx, "bssid", "mac")
        if (bssid.isBlank()) return null
        val ssid = cols.valueOf(idx, "ssid", "topssid").ifBlank { "<hidden>" }
        val security = cols.valueOf(idx, "security", "authmode", "encryption")
        val channel = cols.valueOf(idx, "channel", "chan").toIntOrNull()
        val rssi = cols.valueOf(idx, "rssi", "bestrssi").toIntOrNull()
        val lat = cols.valueOf(idx, "latitude", "lat", "centroidlat").toDoubleOrNull()
        val lon = cols.valueOf(idx, "longitude", "lon", "centroidlon").toDoubleOrNull()
        return ParsedEvidence(
            bssid = bssid,
            ssid = ssid,
            security = security,
            channel = channel,
            rssi = rssi,
            latitude = lat,
            longitude = lon,
            seenAt = System.currentTimeMillis()
        )
    }

    private fun isWardriveMasterHeader(idx: Map<String, Int>): Boolean {
        return idx.containsKey("mac") && idx.containsKey("authmode") && idx.containsKey("centroidlat") && idx.containsKey("centroidlon")
    }

    private fun isGenericEvidenceHeader(idx: Map<String, Int>): Boolean {
        val hasId = idx.containsKey("bssid") || idx.containsKey("mac")
        val hasGeo = idx.containsKey("latitude") || idx.containsKey("lat") || idx.containsKey("centroidlat")
        return hasId && hasGeo
    }

    private fun parseCsvLine(line: String): List<String> {
        val out = mutableListOf<String>()
        val cur = StringBuilder()
        var inQuotes = false
        var i = 0
        while (i < line.length) {
            val ch = line[i]
            if (ch == '"') {
                if (inQuotes && i + 1 < line.length && line[i + 1] == '"') {
                    cur.append('"')
                    i += 2
                    continue
                }
                inQuotes = !inQuotes
                i += 1
                continue
            }
            if (ch == ',' && !inQuotes) {
                out += cur.toString()
                cur.clear()
            } else {
                cur.append(ch)
            }
            i += 1
        }
        out += cur.toString()
        return out
    }

    private fun List<String>.valueOf(idx: Map<String, Int>, vararg keys: String): String {
        for (key in keys) {
            val i = idx[key.lowercase(Locale.US)] ?: continue
            return getOrNull(i)?.trim().orEmpty()
        }
        return ""
    }
}
