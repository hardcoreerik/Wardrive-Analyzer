package com.wardrive.analyzer.android.marauder

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class MarauderFileToolsTest {
    @Test
    fun classifiesCommonMarauderFiles() {
        assertEquals(MarauderImportFileType.PCAP, MarauderFileClassifier.classify("beacon_0.pcap"))
        assertEquals(MarauderImportFileType.WARDRIVE_CSV, MarauderFileClassifier.classify("wardrive_1.csv"))
        assertEquals(MarauderImportFileType.LOG, MarauderFileClassifier.classify("notes.log"))
        assertTrue(MarauderFileClassifier.isLikelyMarauderFile("evilportal_capture.txt"))
    }

    @Test
    fun hashesBytesWithSha256() {
        assertEquals(
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            Sha256.hashBytes("hello".toByteArray())
        )
    }
}
