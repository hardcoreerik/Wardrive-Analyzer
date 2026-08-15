# OrcAlyzer

(Formerly Wardrive Analyzer.) Wardrive evidence analysis across desktop, Android, and the M5Stack Tab5 field device, unified into one repo. It ingests Wi-Fi logs and PCAPs, normalizes observations into a local project vault, and produces analyst-ready exports and visual reports.

## Repo Layout

- **Desktop** (this directory) — the primary PySide6 analysis app; see Main Components below.
- **`android-app/`** — Android-native evidence analyzer (local parsing, map workflows, sync).
- **`tab5-firmware/`** — M5Stack Tab5 (ESP32-P4) field firmware: WiFi scanning, and a Companion Link client that talks to the desktop app. ESP-IDF only — see `tab5-firmware/project_truth.md` before touching its build setup.

## Core Value

- Local-first evidence workflow
- Repeatable ingestion and analysis pipeline
- Operator-facing desktop UX for rapid triage and reporting

## Main Components

- `gui_step3d_scene.py` - primary PySide6 desktop interface
- `core/parser_logs.py` - wardrive log parser
- `core/parser_pcap.py` - packet evidence parser
- `core/analyze.py` - analysis orchestration
- `project_vault.py` - project persistence and evidence indexing
- `core/writers.py` - report/export generation

## Quick Start

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
python run_step3d_scene.py
```

## Test

```powershell
pip install -r requirements-dev.txt
python -m pytest tests/ -v
```

## Output Artifacts

- CSV/XLSX exports
- KML geospatial output
- HTML summary reports
- PCAP-centric analysis reports

## Governance

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)
- [CHANGELOG.md](CHANGELOG.md)
