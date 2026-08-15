package com.wardrive.analyzer.android.marauder

import java.text.SimpleDateFormat
import java.util.Locale
import java.util.TimeZone

class MarauderOutputParser {
    fun parseLine(rawLine: String, now: Long = System.currentTimeMillis()): MarauderParseResult {
        val line = rawLine.trim()
        if (line.isBlank()) return MarauderParseResult()

        val bssids = macRegex.findAll(line).map { it.value.uppercase(Locale.US) }.toList()
        val channel = findInt(line, channelRegex)
        val rssi = findInt(line, rssiRegex) ?: dbmRegex.find(line)?.groupValues?.getOrNull(1)?.toIntOrNull()
        val ssid = ssidRegex.find(line)?.groupValues?.getOrNull(1)?.trim()?.trim('"')
        val encryption = encryptionRegex.find(line)?.groupValues?.getOrNull(1)?.trim()
        val lat = findDouble(line, latRegex)
        val lon = findDouble(line, lonRegex)
        val accuracy = findDouble(line, accuracyRegex)
        val timestamp = parseTimestamp(line)

        val wardrive = if (bssids.isNotEmpty() && (lat != null || lon != null || line.contains("wardrive", true))) {
            MarauderWardriveRecord(
                ssid = ssid,
                bssid = bssids.firstOrNull(),
                rssi = rssi,
                channel = channel,
                encryption = encryption,
                latitude = lat,
                longitude = lon,
                accuracy = accuracy,
                timestamp = timestamp ?: now,
                rawLine = rawLine
            )
        } else {
            null
        }

        val stationHint = line.contains("station", true) ||
            line.contains("client", true) ||
            line.contains("sta", true)
        val station = if (bssids.isNotEmpty() && stationHint && ssid == null) {
            MarauderStation(
                mac = bssids.first(),
                associatedBssid = bssids.drop(1).firstOrNull(),
                rssi = rssi,
                channel = channel,
                rawLine = rawLine,
                firstSeen = now,
                lastSeen = now
            )
        } else {
            null
        }

        val apHint = line.contains("ap", true) ||
            line.contains("ssid", true) ||
            line.contains("beacon", true) ||
            line.contains("bssid", true)
        val ap = if (bssids.isNotEmpty() && apHint && station == null) {
            MarauderAccessPoint(
                ssid = ssid?.ifBlank { "<hidden>" } ?: "<unknown>",
                bssid = bssids.first(),
                channel = channel,
                rssi = rssi,
                encryption = encryption,
                rawLine = rawLine,
                firstSeen = now,
                lastSeen = now
            )
        } else {
            null
        }

        return MarauderParseResult(
            accessPoint = ap,
            station = station,
            wardriveRecord = wardrive
        )
    }

    private fun findInt(line: String, regex: Regex): Int? =
        regex.find(line)?.groupValues?.getOrNull(1)?.toIntOrNull()

    private fun findDouble(line: String, regex: Regex): Double? =
        regex.find(line)?.groupValues?.getOrNull(1)?.toDoubleOrNull()

    private fun parseTimestamp(line: String): Long? {
        val value = timestampRegex.find(line)?.groupValues?.getOrNull(1)?.trim() ?: return null
        timestampFormats.forEach { format ->
            try {
                return format.parse(value)?.time
            } catch (_: Exception) {
            }
        }
        return value.toLongOrNull()
    }

    companion object {
        private val macRegex = Regex("""(?i)\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b|\b[0-9a-f]{2}(?:-[0-9a-f]{2}){5}\b""")
        private val channelRegex = Regex("""(?i)\b(?:ch|chan|channel)\s*[:=]?\s*(\d{1,3})\b""")
        private val rssiRegex = Regex("""(?i)\b(?:rssi|signal|sig|power)\s*[:=]?\s*(-?\d{1,3})\b""")
        private val dbmRegex = Regex("""(-?\d{1,3})\s*dBm\b""", RegexOption.IGNORE_CASE)
        private val ssidRegex = Regex("""(?i)\bssid\s*[:=]\s*([^,;\]|]+)""")
        private val encryptionRegex = Regex("""(?i)\b(?:auth|enc|encryption|security)\s*[:=]\s*([A-Za-z0-9_./+-]+)""")
        private val latRegex = Regex("""(?i)\b(?:lat|latitude)\s*[:=]\s*(-?\d+(?:\.\d+)?)""")
        private val lonRegex = Regex("""(?i)\b(?:lon|lng|longitude)\s*[:=]\s*(-?\d+(?:\.\d+)?)""")
        private val accuracyRegex = Regex("""(?i)\b(?:acc|accuracy)\s*[:=]\s*(\d+(?:\.\d+)?)""")
        private val timestampRegex = Regex("""(?i)\b(?:timestamp|time|date)\s*[:=]\s*([^,;\]|]+)""")
        private val timestampFormats = listOf(
            "yyyy-MM-dd HH:mm:ss",
            "yyyy-MM-dd'T'HH:mm:ss'Z'",
            "MM/dd/yyyy HH:mm:ss"
        ).map {
            SimpleDateFormat(it, Locale.US).apply { timeZone = TimeZone.getTimeZone("UTC") }
        }
    }
}
