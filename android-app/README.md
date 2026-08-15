# Wardrive Analyzer Android

Android-native field companion for authorized wardrive evidence workflows. The app ingests synced archives, parses wireless evidence, stores results locally, and renders map/report views optimized for on-device analysis.

## Core Capabilities

- Kotlin + Jetpack Compose application shell
- Evidence ingestion for CSV/log/PCAP-oriented project bundles
- Local persistence with Room
- Interactive map and report surfaces
- Dropbox project sync support from in-app settings

## Screens

- `Home` - project status and sync health
- `Live` - streaming and latest observations
- `Map` - map-first evidence exploration
- `Files` - project artifacts and imports
- `Settings` - Dropbox and runtime configuration

## Build

```powershell
.\gradlew.bat assembleDebug
.\gradlew.bat assembleRelease
```

Artifacts:

- `app/build/outputs/apk/debug/app-debug.apk`
- `app/build/outputs/apk/release/app-release.apk`

## Install

Use release assets from GitHub Releases or install locally with ADB:

```powershell
adb install -r app\build\outputs\apk\debug\app-debug.apk
```

## Development Standards

- CI validates build/test on pull requests
- Changes should include validation notes in PRs
- Security-sensitive values must remain out of source

## Project Docs

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)
- [CHANGELOG.md](CHANGELOG.md)
