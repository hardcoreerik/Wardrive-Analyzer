package com.wardrive.analyzer.android.marauder

import java.io.File
import java.io.InputStream
import java.security.MessageDigest
import java.util.Locale

object MarauderFileClassifier {
    private val keywordRegex = Regex("""(?i)(wardrive|marauder|sniff|probe|beacon|deauth|gps|evilportal)""")

    fun classify(fileName: String): MarauderImportFileType {
        val lower = fileName.lowercase(Locale.US)
        return when {
            lower.endsWith(".pcap") || lower.endsWith(".pcapng") || lower.endsWith(".cap") -> MarauderImportFileType.PCAP
            lower.endsWith(".csv") && (lower.startsWith("wardrive_") || keywordRegex.containsMatchIn(lower)) ->
                MarauderImportFileType.WARDRIVE_CSV
            lower.endsWith(".log") || lower.endsWith(".txt") -> {
                if (lower.startsWith("wardrive_") || keywordRegex.containsMatchIn(lower)) {
                    MarauderImportFileType.WARDRIVE_CSV
                } else {
                    MarauderImportFileType.LOG
                }
            }
            lower.endsWith(".csv") -> MarauderImportFileType.WARDRIVE_CSV
            else -> MarauderImportFileType.UNKNOWN
        }
    }

    fun isLikelyMarauderFile(fileName: String): Boolean {
        val lower = fileName.lowercase(Locale.US)
        return classify(lower) != MarauderImportFileType.UNKNOWN || keywordRegex.containsMatchIn(lower)
    }
}

object Sha256 {
    fun hashBytes(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(bytes).toHex()
    }

    fun hashFile(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input -> updateDigest(input, digest) }
        return digest.digest().toHex()
    }

    private fun updateDigest(input: InputStream, digest: MessageDigest) {
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        while (true) {
            val read = input.read(buffer)
            if (read <= 0) break
            digest.update(buffer, 0, read)
        }
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
