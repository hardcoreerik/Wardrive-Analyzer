# Wardrive Analyzer

![Python](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python&logoColor=white)
![PySide6](https://img.shields.io/badge/PySide6-desktop-41CD52)
![SQLite](https://img.shields.io/badge/SQLite-project%20vault-003B57)
![Status](https://img.shields.io/badge/Status-local--first%20MVP-6A5ACD)

Wardrive Analyzer is a Windows-first desktop tool for organizing authorized WiFi wardrive evidence. It ingests logs and PCAPs, stores evidence in a local project vault, analyzes RF observations, and exports CSV, XLSX, KML, HTML map, and PCAP summary reports.

## Features

| Area | Files | Description |
| --- | --- | --- |
| Desktop shell | `run_step3d_scene.py`, `gui_step3d_scene.py` | PySide6 Mission Control interface with project, ingest, run, report, and console surfaces |
| Project vault | `project_vault.py` | SQLite-backed project metadata, evidence discovery, dedupe, and ingest |
| Log parser | `core/parser_logs.py` | WiGLE-style wardrive log parsing and sighting extraction |
| PCAP parser | `core/parser_pcap.py` | Parallel dpkt-based PCAP parsing for AP, station, EAPOL, and channel evidence |
| Analysis pipeline | `core/analyze.py` | Report orchestration and run manifest updates |
| Writers | `core/writers.py` | CSV, XLSX, KML, map, summary, and PCAP report generation |
| Build helpers | `build_nuitka.py`, `WardriveAnalyzer.spec` | Local packaging helpers |

## Quick Start

Create or activate a Python 3.11+ environment, then install the runtime dependencies used by the app.

```powershell
cd "F:\Ai\WardriveAPP\Wardrive Analyzer"
python -m venv .venv
.\.venv\Scripts\activate
pip install PySide6 dpkt openpyxl
python run_step3d_scene.py
```

The local launcher can also be used from Windows:

```powershell
.\launch.cmd
```

## Expected Workflow

1. Launch the app.
2. Select or create a project folder.
3. Scan an SD card or local evidence folder.
4. Attach selected evidence to the project vault.
5. Run analysis.
6. Review generated reports under the project's `runs/` folder.

## Evidence Handling

Wardrive files can contain location data, device identifiers, RF observations, and other sensitive local evidence.

- Use this tool only with data you are authorized to collect and analyze.
- Do not commit `Projects/`, evidence folders, generated exports, logs, databases, or private captures.
- Prefer redacted samples or synthetic fixtures for future tests.
- Keep local API keys, tokens, and personal notes out of Git.

## Collaboration

This repository is shared between Codex and Claude Code.

- Stable branch: `master`
- Codex task branches: `codex/<short-task-name>`
- Claude task branches: `claude/<short-task-name>`
- Collaboration protocol: [docs/agent-collaboration.md](docs/agent-collaboration.md)
- Codex instructions: [AGENTS.md](AGENTS.md)
- Claude instructions: [CLAUDE.md](CLAUDE.md)

Use pull requests as the visible handoff channel. Uncommitted local edits are invisible to the other agent.

## AI Bridge

Local agents can inspect and operate the project through JSON commands without opening a network service.

```powershell
python wardrive_cli.py project-summary "F:\WardriveAnalytics"
python wardrive_cli.py latest-run "F:\WardriveAnalytics"
python wardrive_cli.py analyze-project "F:\WardriveAnalytics" --events
```

See [docs/ai-bridge.md](docs/ai-bridge.md).

## Verification

Useful checks:

```powershell
python -m py_compile run_step3d_scene.py gui_step3d_scene.py project_vault.py core\analyze.py core\parser_logs.py core\parser_pcap.py
git diff --check
```

For GUI changes, verify that a visible window titled `Wardrive Mission Control` opens.

```powershell
.\.venv\Scripts\pythonw.exe run_step3d_scene.py
```

## Project Structure

```text
Wardrive Analyzer/
|-- run_step3d_scene.py       # App entrypoint
|-- gui_step3d_scene.py       # PySide6 Mission Control UI
|-- project_vault.py          # Project vault, SD scan, ingest, dedupe
|-- wardrive_service.py       # Shared local service functions for GUI/CLI/agents
|-- wardrive_cli.py           # JSON CLI and stdio bridge for local agents
|-- core/
|   |-- analyze.py            # Report orchestration
|   |-- parser_logs.py        # Wardrive log parsing
|   |-- parser_pcap.py        # PCAP parsing
|   |-- geo.py                # Centroid, stability, risk helpers
|   |-- writers.py            # Report writers
|   `-- project.py            # Run folder and manifest helpers
|-- assets/                   # UI and offline map assets
|-- Projects/                 # Local evidence and reports, gitignored
`-- docs/
    `-- agent-collaboration.md
```

## Status

This is an active local MVP. Favor working desktop behavior, careful evidence handling, and clear agent handoffs over large architecture rewrites.
