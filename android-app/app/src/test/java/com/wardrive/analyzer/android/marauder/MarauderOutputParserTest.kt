package com.wardrive.analyzer.android.marauder

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

class MarauderOutputParserTest {
    private val parser = MarauderOutputParser()

    @Test
    fun parsesAccessPointLine() {
        val result = parser.parseLine(
            "AP SSID: TestNet BSSID: AA:BB:CC:DD:EE:FF CH: 6 RSSI: -47 ENC: WPA2",
            now = 1000L
        )

        assertNotNull(result.accessPoint)
        assertEquals("AA:BB:CC:DD:EE:FF", result.accessPoint?.bssid)
        assertEquals(6, result.accessPoint?.channel)
        assertEquals(-47, result.accessPoint?.rssi)
    }

    @Test
    fun keepsGpsWardriveRecordWhenPresent() {
        val result = parser.parseLine(
            "wardrive ssid=Shop bssid=10:20:30:40:50:60 rssi=-70 channel=11 lat=45.1 lon=-122.2",
            now = 2000L
        )

        assertNotNull(result.wardriveRecord)
        assertEquals("10:20:30:40:50:60", result.wardriveRecord?.bssid)
        assertEquals(45.1, result.wardriveRecord?.latitude ?: 0.0, 0.0001)
    }
}
