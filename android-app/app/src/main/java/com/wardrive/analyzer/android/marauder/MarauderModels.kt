package com.wardrive.analyzer.android.marauder

enum class MarauderConnectionStatus {
    DISCONNECTED,
    PERMISSION_REQUIRED,
    CONNECTING,
    CONNECTED,
    ERROR
}

data class MarauderDeviceInfo(
    val deviceName: String = "No Marauder connected",
    val vendorId: Int? = null,
    val productId: Int? = null,
    val driverName: String? = null
)

data class MarauderConnectionUiState(
    val status: MarauderConnectionStatus = MarauderConnectionStatus.DISCONNECTED,
    val device: MarauderDeviceInfo? = null,
    val message: String = "No Marauder connected"
)

data class MarauderAccessPoint(
    val ssid: String,
    val bssid: String,
    val channel: Int?,
    val rssi: Int?,
    val encryption: String?,
    val rawLine: String,
    val firstSeen: Long,
    val lastSeen: Long
)

data class MarauderStation(
    val mac: String,
    val associatedBssid: String?,
    val rssi: Int?,
    val channel: Int?,
    val rawLine: String,
    val firstSeen: Long,
    val lastSeen: Long
)

data class MarauderWardriveRecord(
    val ssid: String?,
    val bssid: String?,
    val rssi: Int?,
    val channel: Int?,
    val encryption: String?,
    val latitude: Double?,
    val longitude: Double?,
    val accuracy: Double?,
    val timestamp: Long?,
    val rawLine: String
)

data class MarauderParseResult(
    val accessPoint: MarauderAccessPoint? = null,
    val station: MarauderStation? = null,
    val wardriveRecord: MarauderWardriveRecord? = null
)

enum class MarauderImportFileType {
    WARDRIVE_CSV,
    PCAP,
    LOG,
    UNKNOWN
}

enum class MarauderMascotState {
    CONNECT,
    SCAN,
    EXPORT,
    SYNC,
    WARNING,
    SUCCESS
}
