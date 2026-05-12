# AI Bridge

Wardrive Analyzer exposes a local JSON bridge for Codex, Claude, and other local agents. It does not open a network port.

## One-Shot CLI

All commands print JSON to stdout.

```powershell
python wardrive_cli.py project-summary "F:\WardriveAnalytics"
python wardrive_cli.py evidence-list "F:\WardriveAnalytics" --limit 25
python wardrive_cli.py runs-list "F:\WardriveAnalytics" --limit 10
python wardrive_cli.py latest-run "F:\WardriveAnalytics"
python wardrive_cli.py summarize-latest-run "F:\WardriveAnalytics"
python wardrive_cli.py strongest-unknown-aps "F:\WardriveAnalytics" --limit 25
python wardrive_cli.py compare-latest-runs "F:\WardriveAnalytics"
python wardrive_cli.py suspicious-handshakes "F:\WardriveAnalytics" --limit 25
python wardrive_cli.py evidence-health "F:\WardriveAnalytics"
python wardrive_cli.py scan-folder "G:\" --limit 50
python wardrive_cli.py analyze-project "F:\WardriveAnalytics" --events
```

`analyze-project` generates a new run folder under the project. Use it only when the operator wants a fresh report.

## Stdio JSON Bridge

Agents can keep one process open and send one JSON object per line.

```powershell
python wardrive_cli.py serve-stdio
```

Request format:

```json
{"id":"1","action":"project_summary","params":{"project":"F:\\WardriveAnalytics"}}
```

Response format:

```json
{"status":"ok","id":"1","project_dir":"F:\\WardriveAnalytics"}
```

Supported actions:

| Action | Params | Mutates |
| --- | --- | --- |
| `project_summary` | `project`, optional `import_limit` | Ensures project vault exists |
| `evidence_list` | `project`, optional `limit`, `offset` | No |
| `runs_list` | `project`, optional `limit` | No |
| `latest_run` | `project` | No |
| `summarize_latest_run` | `project`, optional `top` | No |
| `strongest_unknown_aps` | `project`, optional `limit` | No |
| `compare_latest_runs` | `project` | No |
| `suspicious_handshakes` | `project`, optional `limit` | No |
| `evidence_health` | `project` | No |
| `integration_plan` | None | No |
| `scan_folder` | `folder`, optional `limit`, `include_hidden` | No |
| `analyze_project` | `project` | Yes, creates a new run |

## Agent-Friendly Analysis Actions

- `summarize_latest_run` gives an executive-style JSON summary with AP totals, risk tiers, auth counts, top risky APs, and "what changed since last run."
- `strongest_unknown_aps` finds high-signal hidden, unknown, or incomplete AP records sorted by signal strength.
- `compare_latest_runs` compares the two newest `wardrive_master.csv` outputs by BSSID/MAC and highlights added, missing, and changed networks.
- `suspicious_handshakes` surfaces packet-level handshake/EAPOL evidence from `pcap_bssid_master.csv`.
- `evidence_health` reports duplicate evidence rows, missing source files, latest missing report artifacts, and PCAP summaries that decoded no frames.

## Safety

- The bridge is local-only.
- It returns paths and evidence metadata, not raw capture contents.
- Do not commit generated reports, evidence, local logs, or `error_reports/`.
- Prefer read-only commands before `analyze_project`.
