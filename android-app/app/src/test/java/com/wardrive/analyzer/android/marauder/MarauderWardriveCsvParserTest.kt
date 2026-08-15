package com.wardrive.analyzer.android.marauder

import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.BufferedReader
import java.io.StringReader

class MarauderWardriveCsvParserTest {
    private val parser = MarauderWardriveCsvParser()

    @Test
    fun parsesHeaderVariant() {
        val csv = """
            Network Name,MAC,Signal,Ch,Auth,Latitude,Longitude,Time
            Cafe,AA:BB:CC:DD:EE:01,-55,1,WPA2,45.0,-122.0,2026-05-15 12:00:00
        """.trimIndent()

        val rows = parser.parse(BufferedReader(StringReader(csv)))

        assertEquals(1, rows.size)
        assertEquals("Cafe", rows.first().ssid)
        assertEquals("AA:BB:CC:DD:EE:01", rows.first().bssid)
        assertEquals(-55, rows.first().rssi)
    }

    @Test
    fun bestEffortWithoutHeader() {
        val csv = "AA:BB:CC:DD:EE:02,Garage,WPA2,6,-80,45.2,-122.3"

        val rows = parser.parse(BufferedReader(StringReader(csv)))

        assertEquals(1, rows.size)
        assertEquals("Garage", rows.first().ssid)
        assertEquals("AA:BB:CC:DD:EE:02", rows.first().bssid)
    }
}
