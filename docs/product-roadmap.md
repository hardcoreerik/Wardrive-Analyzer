# Wardrive Analyzer Product Roadmap

This roadmap keeps the tool local-first while borrowing the strongest operator workflows from NetSpot, Ekahau, Wireshark, WiGLE, Kismet, airodump-ng, and Wireshark/PCAP workflows.

## Phase 1: Agent-Readable Intelligence

Status: started.

- Add read-only AI bridge actions for latest-run summary, strongest unknown APs, run comparison, suspicious handshakes, and evidence health.
- Keep the bridge local-only through `wardrive_cli.py` and `wardrive_service.py`.
- Return structured JSON that Claude, Codex, and future MCP wrappers can call without scraping GUI text.
- Preserve raw evidence boundaries: return metadata, paths, counts, and findings, not capture payload dumps.

## Phase 2: Import Adapters

Planned adapters:

- Kismet `.kismet` SQLite: devices, SSIDs, channels, encryption, signal, timestamps, GPS when present.
- Kismet CSV: lightweight import for exported device tables.
- WiGLE CSV: observed networks, lat/lon, encryption, channel, signal, and last-seen fields.
- airodump-ng CSV: AP and station sections, privacy/cipher/auth, beacons, power, channel, and ESSID.
- Wireshark PCAP metadata: packet-level AP, station, EAPOL, channel, and RSSI metadata without exposing packet payloads in agent responses.
- Bluetooth/BLE adapter: planned separately once a source format is selected; normalize device MAC/identifier, name, RSSI, timestamps, and location observations into the same repeated-sighting model.

Design notes:

- Normalize imports into the project vault before analysis.
- Store adapter name, source path, hash, imported row count, and warnings for chain-of-custody.
- Warn on duplicate imports by file hash and by overlapping BSSID/source/timestamp combinations.

## Phase 3: Packet-Level Filters

The Wireshark-inspired analyzer should become a guided filter surface, not a raw packet wall.

Initial dropdown filters:

- Handshake state: none, EAPOL seen, partial, full 4-way.
- Frame role: AP, station, management, data, EAPOL.
- AP status: known in logs, PCAP-only, hidden SSID, open auth, high risk.
- Signal bands: strong, medium, weak, unknown.
- Vendor/category once OUI enrichment is available in CSV exports.

## Phase 4: Survey Maps And Floorplans

Map upgrades should move toward NetSpot/Ekahau-style survey review.

- Confidence circles around AP centroids.
- Run comparison overlay for added, missing, and changed networks.
- Filters by auth, risk tier, vendor/category, channel, and handshake state.
- Floorplan import with calibration points.
- Heatmaps by signal strength, AP density, risk tier, and channel congestion.
- Clear visual distinction between GPS-derived points, inferred centroids, and floorplan-estimated points.

## Phase 5: Global Wireless Database Integration

WiGLE integration should be optional, cached, and explicit.

- Import WiGLE CSV immediately as an offline adapter.
- Add API enrichment later behind a user-provided key and a clear "enrich selected run" action.
- Cache lookups locally by BSSID and avoid repeated queries.
- Mark external database matches separately from locally observed evidence.
- Never let global database results overwrite local capture truth; treat them as enrichment.

## Phase 6: Reports

Report quality targets:

- Cleaner executive summary with AP counts, risk tiers, open/hidden/handshake totals, and strongest unknown APs.
- "What changed since last run" section powered by `compare_latest_runs`.
- Evidence health section for corrupt/empty PCAPs, duplicate imports, missing files, and sanitation warnings.
- Risk-tier language that is readable by non-technical stakeholders while still linking to exact evidence rows.
- Repeated-sighting sections that call out APs seen across multiple files or days, with first/last seen, active-day count, source-file count, confidence radius, and location quality.
- Map/KML popups should expose the same repeated-sighting fields so the HTML report and geospatial exports agree.

## Phase 7: MCP Wrapper

The MCP server should wrap `wardrive_service.py`, not duplicate analyzer logic.

Candidate tools:

- `wardrive_project_summary`
- `wardrive_summarize_latest_run`
- `wardrive_strongest_unknown_aps`
- `wardrive_compare_latest_runs`
- `wardrive_suspicious_handshakes`
- `wardrive_evidence_health`
- `wardrive_scan_folder`
- `wardrive_analyze_project`

Safety defaults:

- Read-only tools should be available first.
- Mutating tools, especially fresh analysis generation, should be clearly marked.
- No network listener is required for the current bridge; MCP can run as a local stdio server.
