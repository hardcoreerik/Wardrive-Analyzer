# NEONDRIVE Session Import

Wardrive Analyzer can import wireless validation evidence collected by NEONDRIVE
firmware devices and uploaded via Dropbox.

---

## How to Import a Session

### Prerequisites

- NEONDRIVE device has completed a capture session.
- Technician clicked **Sync to Dropbox** on the NEONDRIVE `/analyzer` web page.
- Dropbox desktop app has synced the session to the local PC.

### Import Steps

1. Open Wardrive Analyzer and select or create a project.
2. Go to the **SD Ingest** tab.
3. Click **Import NEONDRIVE Session…**
4. In the file dialog, navigate to the Dropbox-synced session folder.
   - Default path: `<Dropbox root>/WardriveAnalyzerSync/neondrive/incoming/<device_id>/sessions/<session_id>/`
   - The folder name will look like: `ND-CYD35-0001-SP3CTER-T0000300`
5. Click **Select Folder**.
6. Wardrive Analyzer validates and imports the bundle.
7. A dialog confirms the result (imported / already imported / error).
8. Run analysis from the Evidence Vault.

---

## Expected Folder Layout

```
ND-CYD35-0001-SP3CTER-T0000300/
  manifest.json             ← required — neondrive.session.v1
  sync_complete.flag        ← required — upload completion marker
  summary.json              ← optional — quick display status
  events.csv                ← optional — event timeline
  artifacts/
    handshakes.pcap         ← optional — EAPOL handshake PCAP
    raw.pcap                ← optional — raw monitor-mode PCAP
    beacon.pcap             ← optional — beacon frame PCAP
    specter.hc22000         ← optional — hashcat 22000 PMKID/MIC export
    stats.csv               ← optional — per-interval statistics
  logs/
    capture_summary.txt     ← optional — human-readable session summary
    jammit_session.log      ← optional — JAMMIT module log
```

---

## Required Files

| File | Why required |
|---|---|
| `manifest.json` | Session metadata, schema version, device identity, target info |
| `sync_complete.flag` | Atomicity guard — confirms Dropbox upload completed |

If either file is missing, the import is rejected as incomplete.

---

## Supported Schema

Currently: `neondrive.session.v1`

The `schema` field in `manifest.json` must match a supported version. Unknown
schema versions are rejected — update Wardrive Analyzer to add support.

---

## Evidence Mapping in Project Vault

| Bundle File | `source_app` | `kind` | `recommended` |
|---|---|---|---|
| `manifest.json` | `neondrive` | `neondrive_meta` | No |
| `summary.json` | `neondrive` | `neondrive_meta` | No |
| `events.csv` | `neondrive` | `neondrive_events` | Yes |
| `*.pcap`, `*.pcapng` | `neondrive` | `pcap_neondrive` | Yes |
| `specter.hc22000`, `*.22000` | `neondrive` | `handshake_22000` | Yes |
| `stats.csv` | `neondrive` | `neondrive_session_log` | No |
| `sync_complete.flag` | `neondrive` | `neondrive_flag` | No |

`handshake_22000` files are fed into the existing EAPOL/handshake analysis pipeline.
PCAP files are fed into the existing dpkt-based PCAP parser.

---

## Idempotency

Import is idempotent. Re-importing the same session folder produces status
`already_imported` — no duplicate evidence records are created. Deduplication
uses SHA-256 content hash.

---

## Session ID Format

`ND-<BOARD>-<SEQ>-<MODULE>-T<BOOT_SECONDS>`

| Part | Example | Description |
|---|---|---|
| `BOARD` | `CYD35` | NEONDRIVE hardware target |
| `SEQ` | `0001` | Monotonic session counter (stored on SD) |
| `MODULE` | `SP3CTER` | Capture module that ran |
| `T<SEC>` | `T0000300` | Boot-relative seconds (device has no RTC) |

The device ID used in the Dropbox path is `ND-<BOARD>-<MAC_SUFFIX>`.

---

## Running Analysis After Import

After import, the imported evidence files appear in the Evidence Vault tab with
`source_app = "neondrive"`. Use the standard "Analyze Imported Evidence (Project)"
button to run the full analysis pipeline, which includes:

- PCAP parsing (802.11 frame analysis, EAPOL handshake confidence)
- Handshake hash file cataloguing
- Report generation (HTML, CSV, KML, JSON)

---

## Security Notes

- Wardrive Analyzer never executes any file from the imported bundle.
- Files with executable extensions (`.exe`, `.bat`, `.sh`, `.py`, etc.) are
  automatically rejected.
- Path traversal attempts in artifact paths are detected and rejected.
- Imported PCAPs and hash files are treated as evidence from an authorized
  controlled lab engagement.

---

## Troubleshooting

| Problem | Resolution |
|---|---|
| "sync_complete.flag not present" | NEONDRIVE sync did not complete. Check device `/analyzer` page and retry sync. |
| "unsupported schema" | NEONDRIVE firmware is newer than this Wardrive Analyzer. Update the app. |
| "already imported" | Session was previously imported. Evidence is safe to use as-is. |
| PCAP not appearing in analysis | Check that the PCAP contains 802.11 frames (LINKTYPE 127). Raw Ethernet PCAPs are not supported. |
| Hash file not cracking | `.hc22000` format requires hashcat mode 22000. Verify the file is not empty. |

---

## Future: Bidirectional Writeback (v2 Roadmap)

After Wardrive Analyzer processes a session, it could write results back to the
same Dropbox folder:

```
sessions/<session_id>/
  analysis.json        ← full scored result
  report.html          ← evidence report
  remediation.json     ← recommended remediation steps
```

NEONDRIVE firmware would then poll `/analyzer` to show the scored result from
Wardrive Analyzer alongside the local quick verdict. This is planned for v2.

See [`docs/WARDRIVE_ANALYZER_SYNC.md`](../NEONDRIVE-side/WARDRIVE_ANALYZER_SYNC.md)
in the NEONDRIVE repo for the full product loop description.
