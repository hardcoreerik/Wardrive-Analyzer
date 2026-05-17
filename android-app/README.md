# Wardrive Analyzer Android

Android-native buildout of Wardrive Analyzer Mission Control.

## Current status (v0.1.0)

Implemented:
- Kotlin + Jetpack Compose app shell
- Mission Control tabs: Dashboard, Evidence, Runs, Reports, Import
- Local CSV/log import pipeline with Room persistence
- Run + summary report generation on import

Planned next:
- PCAP metadata ingest parity
- Rich report export parity (CSV/XLSX/KML/HTML)
- Map visualization parity

## Install APK

Prebuilt APKs are published in GitHub Releases.

- `app-release.apk`: installable release build
- `app-debug.apk`: debug build for testing

On Android device:
1. Download APK from Releases.
2. Allow install from unknown sources for your browser/file manager.
3. Open the APK and install.

## Build locally

```powershell
cd "android-app"
.\gradlew.bat assembleDebug
.\gradlew.bat assembleRelease
```

Artifacts:
- `app/build/outputs/apk/debug/app-debug.apk`
- `app/build/outputs/apk/release/app-release.apk`

## Function parity map

Desktop source -> Android target

- `core/parser_logs.py` -> `ingest/WardriveLogParser.kt` (baseline complete)
- `project_vault.py` evidence inventory -> Room entities/DAOs (baseline complete)
- `core/project.py` run manifests -> `RunEntity` and `ReportEntity` (baseline complete)
- `core/parser_pcap.py` -> planned `ingest/PcapIngestService.kt` (pending)
- `core/writers.py` -> planned `export/ReportWriterService.kt` (pending)
- `wardrive_service.py` summaries -> planned `repo/AnalyticsRepository.kt` (pending)
- `assistant_engine.py` / `buddy_ai.py` -> planned `assistant/` module (pending)
