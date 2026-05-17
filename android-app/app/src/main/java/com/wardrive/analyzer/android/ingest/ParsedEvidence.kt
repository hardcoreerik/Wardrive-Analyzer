package com.wardrive.analyzer.android.ingest

data class ParsedEvidence(
    val bssid: String,
    val ssid: String,
    val security: String,
    val channel: Int?,
    val rssi: Int?,
    val latitude: Double?,
    val longitude: Double?,
    val seenAt: Long
)
