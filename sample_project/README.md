# Sample Project

This folder contains synthetic wardrive evidence for testing and demonstration.

No real devices, locations, or credentials are represented.

## Files

- `evidence/sample_wardrive.csv` — 5 synthetic AP records in WiGLE CSV format, covering WPA2, open, hidden, WPA3, and WEP auth types. Coordinates are in the Seattle, WA area.

## Usage

Point Wardrive Analyzer at this folder during development or CI verification:

```powershell
python wardrive_cli.py project-summary sample_project
python wardrive_cli.py evidence-list sample_project
```

Or open the GUI, choose this directory as the project folder, and run analysis.

## Scrubbing Test

Verify the scrub command works against this sample:

```powershell
python wardrive_cli.py scrub-project sample_project --output-dir sample_project_scrubbed --fuzz-gps
```
