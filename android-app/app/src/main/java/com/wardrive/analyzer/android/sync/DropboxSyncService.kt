package com.wardrive.analyzer.android.sync

import android.os.Build
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import org.json.JSONArray
import java.io.BufferedReader
import java.io.ByteArrayInputStream
import java.io.BufferedWriter
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets
import java.time.Instant
import java.time.format.DateTimeParseException
import java.util.Locale
import java.util.zip.ZipInputStream

class DropboxSyncService {
    suspend fun listProjects(
        token: String,
        rootFolder: String,
        appFilesDir: File,
        onStatus: (String) -> Unit = {}
    ): List<ProjectProfile> = withContext(Dispatchers.IO) {
        val cleanToken = token.trim()
        if (cleanToken.isEmpty()) throw IllegalArgumentException("Dropbox access token is required.")
        val root = normalizeProjectRoot(rootFolder)
        onStatus("Marauder: fetching project manifest...")
        val localManifest = File(appFilesDir, "dropbox_projects/projects_manifest.json").apply {
            parentFile?.mkdirs()
        }
        val manifestPath = "$root/projects_manifest.json"
        val profiles = try {
            downloadFile(cleanToken, manifestPath, localManifest)
            parseProjectManifest(localManifest.readText())
        } catch (_: Exception) {
            onStatus("Marauder: manifest not found, scanning folders...")
            listProjectsFromFolders(cleanToken, root)
        }
        profiles.sortedBy { it.displayName.lowercase(Locale.US) }
    }

    suspend fun pullProject(
        token: String,
        rootFolder: String,
        projectSlug: String,
        appFilesDir: File,
        onStatus: (String) -> Unit = {}
    ): PullResult = withContext(Dispatchers.IO) {
        val cleanToken = token.trim()
        if (cleanToken.isEmpty()) throw IllegalArgumentException("Dropbox access token is required.")
        val root = normalizeProjectRoot(rootFolder)
        val remoteProjectRoot = "$root/$projectSlug/Project"
        val localProjectRoot = File(appFilesDir, "dropbox_projects/$projectSlug/Project").apply { mkdirs() }

        onStatus("Marauder: listing project files...")
        val entries = listFolderRecursive(cleanToken, remoteProjectRoot)
        val files = entries.filter { it.optString(".tag") == "file" }
        var downloaded = 0
        var conflicts = 0
        files.forEachIndexed { index, entry ->
            val fullPath = entry.optString("path_display")
            val relPath = fullPath.removePrefix("$remoteProjectRoot/").ifBlank { return@forEachIndexed }
            onStatus("Marauder: pulling ${index + 1}/${files.size} $relPath")
            val localFile = File(localProjectRoot, relPath)
            localFile.parentFile?.mkdirs()
            val tmp = File(localFile.absolutePath + ".tmp")
            downloadFile(cleanToken, fullPath, tmp)
            val remoteTime = parseDropboxTime(entry.optString("server_modified")) ?: System.currentTimeMillis()
            if (localFile.exists()) {
                val localHash = sha256(localFile)
                val remoteHash = sha256(tmp)
                if (localHash != remoteHash) {
                    val ext = localFile.extension
                    val conflictName = if (ext.isBlank()) {
                        "${localFile.name}_android_${deviceTag()}_conflict_${System.currentTimeMillis()}"
                    } else {
                        "${localFile.nameWithoutExtension}_android_${deviceTag()}_conflict_${System.currentTimeMillis()}.$ext"
                    }
                    val conflict = File(localFile.parentFile, conflictName)
                    localFile.copyTo(conflict, overwrite = true)
                    conflicts += 1
                }
            }
            tmp.copyTo(localFile, overwrite = true)
            localFile.setLastModified(remoteTime)
            tmp.delete()
            downloaded += 1
        }
        PullResult(
            projectSlug = projectSlug,
            filesDownloaded = downloaded,
            conflicts = conflicts,
            localProjectDir = localProjectRoot.absolutePath
        )
    }

    suspend fun pushProjectArtifact(
        token: String,
        rootFolder: String,
        projectSlug: String,
        localFile: File,
        relativeProjectPath: String,
        onStatus: (String) -> Unit = {}
    ): SyncRecord = withContext(Dispatchers.IO) {
        val cleanToken = token.trim()
        if (cleanToken.isEmpty()) throw IllegalArgumentException("Dropbox access token is required.")
        val root = normalizeProjectRoot(rootFolder)
        val normalizedRel = relativeProjectPath.trim().replace("\\", "/").trimStart('/')
        val remotePath = "$root/$projectSlug/Project/$normalizedRel"
        ensureRemoteParents(cleanToken, remotePath)
        val existing = getMetadataOrNull(cleanToken, remotePath)
        val uploadPath = if (existing == null) {
            remotePath
        } else {
            val existingHash = existing.optString("content_hash")
            val localHash = sha256(localFile)
            if (existingHash.isNotBlank() && existingHash == localHash) {
                onStatus("Marauder: already synced $normalizedRel")
                return@withContext SyncRecord(
                    projectSlug = projectSlug,
                    direction = "push",
                    path = normalizedRel,
                    status = "skipped",
                    timestamp = System.currentTimeMillis(),
                    conflictFlag = false,
                    message = "Already up to date"
                )
            }
            val ext = localFile.extension
            val suffix = "_android_${deviceTag()}_conflict_${System.currentTimeMillis()}"
            if (ext.isBlank()) "$remotePath$suffix" else remotePath.removeSuffix(".$ext") + "$suffix.$ext"
        }
        onStatus("Marauder: pushing $normalizedRel")
        uploadFile(cleanToken, uploadPath, localFile)
        SyncRecord(
            projectSlug = projectSlug,
            direction = "push",
            path = normalizedRel,
            status = "success",
            timestamp = System.currentTimeMillis(),
            conflictFlag = uploadPath != remotePath,
            message = if (uploadPath != remotePath) "Conflict copy uploaded" else "Uploaded"
        )
    }

    suspend fun ensureProjectInManifest(
        token: String,
        rootFolder: String,
        projectSlug: String,
        displayName: String,
        onStatus: (String) -> Unit = {}
    ) = withContext(Dispatchers.IO) {
        val cleanToken = token.trim()
        if (cleanToken.isBlank()) return@withContext
        val root = normalizeProjectRoot(rootFolder)
        val manifestPath = "$root/projects_manifest.json"
        onStatus("Marauder: updating project manifest...")

        val profiles = try {
            val tmp = File.createTempFile("projects_manifest", ".json")
            downloadFile(cleanToken, manifestPath, tmp)
            val parsed = parseProjectManifest(tmp.readText())
            tmp.delete()
            parsed
        } catch (_: Exception) {
            listProjectsFromFolders(cleanToken, root)
        }.toMutableList()

        val existingIndex = profiles.indexOfFirst { it.slug.equals(projectSlug, ignoreCase = true) }
        val merged = ProjectProfile(
            slug = projectSlug,
            displayName = displayName.ifBlank { projectSlug },
            dropboxPath = "$root/$projectSlug/Project",
            isActive = false,
            lastSyncAt = System.currentTimeMillis()
        )
        if (existingIndex >= 0) {
            profiles[existingIndex] = profiles[existingIndex].copy(
                displayName = merged.displayName,
                dropboxPath = merged.dropboxPath,
                lastSyncAt = merged.lastSyncAt
            )
        } else {
            profiles += merged
        }

        val payload = buildManifestJson(
            profiles.sortedBy { it.displayName.lowercase(Locale.US) }
        )
        uploadBytes(cleanToken, manifestPath, payload.toByteArray(StandardCharsets.UTF_8), overwrite = true)
        onStatus("Marauder: manifest updated for $projectSlug")
    }

    suspend fun syncFromDropbox(
        token: String,
        remoteFolder: String,
        preferredZipName: String?,
        appFilesDir: File,
        onStatus: (String) -> Unit = {}
    ): File = withContext(Dispatchers.IO) {
        val cleanToken = token.trim()
        if (cleanToken.isEmpty()) {
            throw IllegalArgumentException("Dropbox access token is required.")
        }
        val folder = normalizeFolder(remoteFolder)
        val preferredName = preferredZipName?.trim().orEmpty()
        val preferredPath = if (preferredName.isBlank()) null else "$folder/${preferredName.trimStart('/')}"
        val latestPath = "$folder/latest_project.zip"
        val outDir = File(appFilesDir, "dropbox_sync").apply { mkdirs() }
        val zipFile = File(outDir, "latest_project.zip")
        onStatus("Connecting to Dropbox...")
        val downloadPath = try {
            if (preferredPath != null) {
                downloadFile(cleanToken, preferredPath, zipFile)
                preferredPath
            } else {
                downloadFile(cleanToken, latestPath, zipFile)
                latestPath
            }
        } catch (e: Exception) {
            val fallback = if (preferredPath != null && !preferredPath.equals(latestPath, ignoreCase = true)) {
                try {
                    downloadFile(cleanToken, latestPath, zipFile)
                    latestPath
                } catch (_: Exception) {
                    findLatestZipPath(cleanToken, folder)
                }
            } else {
                findLatestZipPath(cleanToken, folder)
            }
                ?: throw RuntimeException(
                    "Could not find requested zip (${preferredName.ifBlank { "latest_project.zip" }}) or any .zip archive in $folder",
                    e
                )
            if (!fallback.equals(latestPath, ignoreCase = true) && !fallback.equals(preferredPath, ignoreCase = true)) {
                onStatus("Marauder: requested zip not found, using ${fallback.substringAfterLast('/')}")
                downloadFile(cleanToken, fallback, zipFile)
            }
            fallback
        }
        onStatus("Extracting project archive...")
        val unzipDir = File(outDir, "latest_project").apply {
            if (exists()) deleteRecursively()
            mkdirs()
        }
        unzip(zipFile, unzipDir)
        onStatus("Dropbox download complete (${downloadPath.substringAfterLast('/')}).")
        unzipDir
    }

    private fun normalizeFolder(path: String): String {
        var p = path.trim()
        if (p.isEmpty()) p = "/WardriveAnalyzerSync"
        if (!p.startsWith("/")) p = "/$p"
        return p.trimEnd('/')
    }

    private fun normalizeProjectRoot(path: String): String {
        var p = path.trim()
        if (p.isEmpty()) p = "/WardriveAnalyzerProjects"
        if (!p.startsWith("/")) p = "/$p"
        return p.trimEnd('/')
    }

    private fun downloadFile(token: String, remotePath: String, outFile: File) {
        val conn = (URL("https://content.dropboxapi.com/2/files/download").openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            doOutput = false
            setRequestProperty("Authorization", "Bearer $token")
            setRequestProperty("Dropbox-API-Arg", JSONObject(mapOf("path" to remotePath)).toString())
            setRequestProperty("Content-Type", "application/octet-stream")
            connectTimeout = 30000
            readTimeout = 120000
        }
        val code = conn.responseCode
        if (code !in 200..299) {
            val err = conn.errorStream?.bufferedReader()?.use { it.readText() } ?: "HTTP $code"
            throw RuntimeException("Dropbox download failed: $err")
        }
        conn.inputStream.use { input ->
            FileOutputStream(outFile).use { output -> input.copyTo(output) }
        }
    }

    private fun uploadFile(token: String, remotePath: String, localFile: File) {
        uploadBytes(token, remotePath, localFile.readBytes(), overwrite = false)
    }

    private fun uploadBytes(token: String, remotePath: String, bytes: ByteArray, overwrite: Boolean) {
        val conn = (URL("https://content.dropboxapi.com/2/files/upload").openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            doOutput = true
            setRequestProperty("Authorization", "Bearer $token")
            setRequestProperty(
                "Dropbox-API-Arg",
                JSONObject(
                    mapOf(
                        "path" to remotePath,
                        "mode" to if (overwrite) "overwrite" else "add",
                        "autorename" to !overwrite,
                        "mute" to false
                    )
                ).toString()
            )
            setRequestProperty("Content-Type", "application/octet-stream")
            connectTimeout = 30000
            readTimeout = 120000
        }
        ByteArrayInputStream(bytes).use { input ->
            conn.outputStream.use { output -> input.copyTo(output) }
        }
        val code = conn.responseCode
        if (code !in 200..299) {
            val err = conn.errorStream?.bufferedReader()?.use { it.readText() } ?: "HTTP $code"
            throw RuntimeException("Dropbox upload failed: $err")
        }
    }

    private fun listFolderRecursive(token: String, path: String): List<JSONObject> {
        val entries = mutableListOf<JSONObject>()
        var response = apiPost(
            token,
            "https://api.dropboxapi.com/2/files/list_folder",
            JSONObject().put("path", path).put("recursive", true).put("include_deleted", false)
        )
        entries += response.getJSONArray("entries").toJsonObjects()
        while (response.optBoolean("has_more")) {
            response = apiPost(
                token,
                "https://api.dropboxapi.com/2/files/list_folder/continue",
                JSONObject().put("cursor", response.getString("cursor"))
            )
            entries += response.getJSONArray("entries").toJsonObjects()
        }
        return entries
    }

    private fun listProjectsFromFolders(token: String, root: String): List<ProjectProfile> {
        val response = apiPost(
            token,
            "https://api.dropboxapi.com/2/files/list_folder",
            JSONObject().put("path", root).put("recursive", false).put("include_deleted", false)
        )
        return response.getJSONArray("entries").toJsonObjects()
            .filter { it.optString(".tag") == "folder" }
            .map {
                val slug = it.optString("name")
                ProjectProfile(
                    slug = slug,
                    displayName = slug.replace('-', ' ').replace('_', ' '),
                    dropboxPath = "$root/$slug/Project"
                )
            }
    }

    private fun findLatestZipPath(token: String, folder: String): String? {
        val response = apiPost(
            token,
            "https://api.dropboxapi.com/2/files/list_folder",
            JSONObject().put("path", folder).put("recursive", false).put("include_deleted", false)
        )
        return response.getJSONArray("entries")
            .toJsonObjects()
            .filter { it.optString(".tag") == "file" }
            .filter { it.optString("name").lowercase(Locale.US).endsWith(".zip") }
            .maxByOrNull { parseDropboxTime(it.optString("server_modified")) ?: 0L }
            ?.optString("path_display")
            ?.takeIf { it.isNotBlank() }
    }

    private fun parseProjectManifest(text: String): List<ProjectProfile> {
        val json = JSONObject(text)
        val array = json.optJSONArray("projects") ?: return emptyList()
        return array.toJsonObjects().mapNotNull { item ->
            val slug = item.optString("slug").trim()
            if (slug.isBlank()) return@mapNotNull null
            ProjectProfile(
                slug = slug,
                displayName = item.optString("displayName").ifBlank { slug },
                dropboxPath = item.optString("dropboxPath").ifBlank { "/WardriveAnalyzerProjects/$slug/Project" },
                isActive = item.optBoolean("isActive", false),
                lastSyncAt = item.optLong("lastSyncAt").takeIf { it > 0L }
            )
        }
    }

    private fun getMetadataOrNull(token: String, path: String): JSONObject? {
        return try {
            apiPost(
                token,
                "https://api.dropboxapi.com/2/files/get_metadata",
                JSONObject().put("path", path)
            )
        } catch (_: Exception) {
            null
        }
    }

    private fun ensureRemoteParents(token: String, path: String) {
        val parent = path.substringBeforeLast('/', "")
        if (parent.isBlank()) return
        val segments = parent.split('/').filter { it.isNotBlank() }
        var current = ""
        segments.forEach {
            current += "/$it"
            try {
                apiPost(
                    token,
                    "https://api.dropboxapi.com/2/files/create_folder_v2",
                    JSONObject().put("path", current).put("autorename", false)
                )
            } catch (_: Exception) {
                // Already exists or not creatable in this segment.
            }
        }
    }

    private fun parseDropboxTime(value: String): Long? {
        if (value.isBlank()) return null
        return try {
            Instant.parse(value).toEpochMilli()
        } catch (_: DateTimeParseException) {
            null
        }
    }

    private fun apiPost(token: String, endpoint: String, payload: JSONObject): JSONObject {
        val conn = (URL(endpoint).openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            doOutput = true
            setRequestProperty("Authorization", "Bearer $token")
            setRequestProperty("Content-Type", "application/json")
            connectTimeout = 30000
            readTimeout = 120000
        }
        BufferedWriter(OutputStreamWriter(conn.outputStream, StandardCharsets.UTF_8)).use {
            it.write(payload.toString())
        }
        val code = conn.responseCode
        val body = if (code in 200..299) {
            BufferedReader(InputStreamReader(conn.inputStream, StandardCharsets.UTF_8)).use { it.readText() }
        } else {
            conn.errorStream?.let {
                BufferedReader(InputStreamReader(it, StandardCharsets.UTF_8)).use { reader -> reader.readText() }
            } ?: "HTTP $code"
        }
        if (code !in 200..299) {
            throw RuntimeException("Dropbox API call failed ($code): $body")
        }
        return if (body.isBlank()) JSONObject() else JSONObject(body)
    }

    private fun sha256(file: File): String {
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        FileInputStream(file).use { input ->
            val buf = ByteArray(8192)
            while (true) {
                val read = input.read(buf)
                if (read <= 0) break
                digest.update(buf, 0, read)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    private fun org.json.JSONArray.toJsonObjects(): List<JSONObject> {
        val out = mutableListOf<JSONObject>()
        for (i in 0 until length()) {
            val obj = optJSONObject(i) ?: continue
            out += obj
        }
        return out
    }

    private fun buildManifestJson(projects: List<ProjectProfile>): String {
        val array = JSONArray()
        projects.forEach { project ->
            array.put(
                JSONObject().apply {
                    put("slug", project.slug)
                    put("displayName", project.displayName)
                    put("dropboxPath", project.dropboxPath)
                    put("isActive", project.isActive)
                    put("lastSyncAt", project.lastSyncAt ?: System.currentTimeMillis())
                }
            )
        }
        return JSONObject().put("projects", array).toString(2)
    }

    private fun deviceTag(): String {
        val model = Build.MODEL?.lowercase(Locale.US).orEmpty()
        val cleaned = model.replace(Regex("""[^a-z0-9]+"""), "_").trim('_')
        return cleaned.ifBlank { "android" }
    }

    private fun unzip(zipFile: File, outputDir: File) {
        ZipInputStream(zipFile.inputStream().buffered()).use { zis ->
            var entry = zis.nextEntry
            while (entry != null) {
                val outFile = File(outputDir, entry.name)
                if (entry.isDirectory) {
                    outFile.mkdirs()
                } else {
                    outFile.parentFile?.mkdirs()
                    FileOutputStream(outFile).use { fos ->
                        zis.copyTo(fos)
                    }
                }
                zis.closeEntry()
                entry = zis.nextEntry
            }
        }
    }
}
