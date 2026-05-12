# AI Bridge

Wardrive Analyzer exposes a local JSON bridge for Codex, Claude, and other local agents. It does not open a network port.

## One-Shot CLI

All commands print JSON to stdout.

```powershell
python wardrive_cli.py project-summary "F:\WardriveAnalytics"
python wardrive_cli.py evidence-list "F:\WardriveAnalytics" --limit 25
python wardrive_cli.py runs-list "F:\WardriveAnalytics" --limit 10
python wardrive_cli.py latest-run "F:\WardriveAnalytics"
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
| `scan_folder` | `folder`, optional `limit`, `include_hidden` | No |
| `analyze_project` | `project` | Yes, creates a new run |

## Safety

- The bridge is local-only.
- It returns paths and evidence metadata, not raw capture contents.
- Do not commit generated reports, evidence, local logs, or `error_reports/`.
- Prefer read-only commands before `analyze_project`.
