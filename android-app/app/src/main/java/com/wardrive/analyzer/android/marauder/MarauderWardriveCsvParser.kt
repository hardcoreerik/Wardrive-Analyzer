package com.wardrive.analyzer.android.marauder

import java.io.BufferedReader
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.TimeZone

class MarauderWardriveCsvParser {
    fun parse(reader: BufferedReader): List<MarauderWardriveRecord> {
        val lines = reader.readLines().filter { it.isNotBlank() }
        if (lines.isEmpty()) return emptyList()
        val firstColumns = splitCsvLine(lines.first())
        val hasHeader = firstColumns.any { column ->
            val normalized = normalize(column)
            normalized in headerAliases.values.flatten()
        }
        val header = if (hasHeader) buildHeaderMap(firstColumns) else emptyMap()
        val dataLines = if (hasHeader) lines.drop(1) else lines

        return dataLines.mapNotNull { raw ->
            val cols = splitCsvLine(raw)
            parseColumns(raw, cols, header)
        }
    }

    private fun parseColumns(
        rawLine: String,
        cols: List<String>,
        header: Map<String, Int>
    ): MarauderWardriveRecord? {
        val bssid = get(cols, header, "bssid") ?: cols.firstOrNull { macRegex.matches(it.trim()) }
        val ssid = get(cols, header, "ssid") ?: bestEffortSsid(cols, bssid)
        val rssi = get(cols, header, "rssi")?.toIntOrNull() ?: cols.mapNotNull { it.trim().toIntOrNull() }.firstOrNull { it in -100..0 }
        val channel = get(cols, header, "channel")?.toIntOrNull() ?: cols.mapNotNull { it.trim().toIntOrNull() }.firstOrNull { it in 1..196 }
        val encryption = get(cols, header, "encryption")
        val latitude = get(cols, header, "latitude")?.toDoubleOrNull() ?: cols.mapNotNull { it.trim().toDoubleOrNull() }.firstOrNull { it in -90.0..90.0 }
        val longitude = get(cols, header, "longitude")?.toDoubleOrNull() ?: cols.mapNotNull { it.trim().toDoubleOrNull() }.firstOrNull { it in -180.0..180.0 && it != latitude }
        val timestamp = parseTime(get(cols, header, "timestamp"))

        if (bssid.isNullOrBlank() && ssid.isNullOrBlank() && latitude == null && longitude == null) return null
        return MarauderWardriveRecord(
            ssid = ssid?.ifBlank { "<hidden>" },
            bssid = bssid?.uppercase(Locale.US),
            rssi = rssi,
            channel = channel,
            encryption = encryption,
            latitude = latitude,
            longitude = longitude,
            accuracy = get(cols, header, "accuracy")?.toDoubleOrNull(),
            timestamp = timestamp,
            rawLine = rawLine
        )
    }

    private fun get(cols: List<String>, header: Map<String, Int>, key: String): String? =
        header[key]?.let { cols.getOrNull(it)?.trim()?.trim('"') }?.takeIf { it.isNotBlank() }

    private fun bestEffortSsid(cols: List<String>, bssid: String?): String? =
        cols.firstOrNull {
            val value = it.trim()
            value.isNotBlank() &&
                value != bssid &&
                !macRegex.matches(value) &&
                value.toIntOrNull() == null &&
                value.toDoubleOrNull() == null
        }?.trim()?.trim('"')

    private fun buildHeaderMap(cols: List<String>): Map<String, Int> {
        val out = mutableMapOf<String, Int>()
        cols.forEachIndexed { index, column ->
            val normalized = normalize(column)
            headerAliases.forEach { (key, aliases) ->
                if (normalized in aliases && key !in out) out[key] = index
            }
        }
        return out
    }

    private fun splitCsvLine(line: String): List<String> {
        val out = mutableListOf<String>()
        val current = StringBuilder()
        var inQuotes = false
        line.forEach { c ->
            when {
                c == '"' -> inQuotes = !inQuotes
                c == ',' && !inQuotes -> {
                    out += current.toString()
                    current.clear()
                }
                else -> current.append(c)
            }
        }
        out += current.toString()
        return out
    }

    private fun parseTime(value: String?): Long? {
        if (value.isNullOrBlank()) return null
        value.toLongOrNull()?.let { return it }
        timestampFormats.forEach { format ->
            try {
                return format.parse(value)?.time
            } catch (_: Exception) {
            }
        }
        return null
    }

    private fun normalize(value: String): String =
        value.trim().lowercase(Locale.US).replace(Regex("""[^a-z0-9]"""), "")

    companion object {
        private val macRegex = Regex("""(?i)[0-9a-f]{2}(?::[0-9a-f]{2}){5}|[0-9a-f]{2}(?:-[0-9a-f]{2}){5}""")
        private val headerAliases = mapOf(
            "ssid" to listOf("ssid", "networkname", "essid"),
            "bssid" to listOf("bssid", "mac", "apmac", "stationmac"),
            "rssi" to listOf("rssi", "signal", "dbm", "power"),
            "channel" to listOf("channel", "ch", "chan"),
            "encryption" to listOf("auth", "encryption", "security", "type"),
            "latitude" to listOf("lat", "latitude"),
            "longitude" to listOf("lon", "lng", "longitude"),
            "accuracy" to listOf("acc", "accuracy"),
            "timestamp" to listOf("timestamp", "time", "date", "lastseen", "firstseen")
        )
        private val timestampFormats = listOf(
            "yyyy-MM-dd HH:mm:ss",
            "yyyy-MM-dd'T'HH:mm:ss'Z'",
            "MM/dd/yyyy HH:mm:ss"
        ).map {
            SimpleDateFormat(it, Locale.US).apply { timeZone = TimeZone.getTimeZone("UTC") }
        }
    }
}
