from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable, Optional

from core.analyze import analyze
from project_vault import (
    discover_project_runs,
    ensure_project_vault,
    evidence_summary,
    gather_project_inputs_for_analysis,
    list_import_history,
    list_project_evidence_detailed,
    scan_sd_folder,
)
from report_intel import (
    compare_latest_runs as build_compare_latest_runs,
    evidence_health as build_evidence_health,
    planned_integration_surface,
    strongest_unknown_aps as build_strongest_unknown_aps,
    summarize_latest_run as build_summarize_latest_run,
    suspicious_handshakes as build_suspicious_handshakes,
)


def _jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in value]
    if hasattr(value, "__dict__"):
        return _jsonable(vars(value))
    return str(value)


def result(status: str, **payload: Any) -> dict[str, Any]:
    body = {"status": status}
    body.update({k: _jsonable(v) for k, v in payload.items()})
    return body


def project_summary(project_dir: str, import_limit: int = 10) -> dict[str, Any]:
    db_path = ensure_project_vault(project_dir)
    logs, pcaps = gather_project_inputs_for_analysis(project_dir)
    runs = discover_project_runs(project_dir)
    latest_run = runs[0] if runs else None
    return result(
        "ok",
        project_dir=os.path.abspath(project_dir),
        db_path=db_path,
        evidence=evidence_summary(project_dir),
        analysis_inputs={"logs": len(logs), "pcaps": len(pcaps)},
        imports=list_import_history(project_dir, limit=import_limit),
        runs_count=len(runs),
        latest_run=latest_run,
    )


def evidence_list(project_dir: str, limit: int = 100, offset: int = 0) -> dict[str, Any]:
    rows = list_project_evidence_detailed(project_dir)
    total = len(rows)
    offset = max(0, int(offset))
    limit = max(0, int(limit))
    page = rows[offset: offset + limit] if limit else rows[offset:]
    return result(
        "ok",
        project_dir=os.path.abspath(project_dir),
        total=total,
        offset=offset,
        limit=limit,
        evidence=page,
    )


def runs_list(project_dir: str, limit: int = 20) -> dict[str, Any]:
    runs = discover_project_runs(project_dir)
    limit = max(0, int(limit))
    return result(
        "ok",
        project_dir=os.path.abspath(project_dir),
        total=len(runs),
        runs=runs[:limit] if limit else runs,
    )


def latest_run(project_dir: str) -> dict[str, Any]:
    runs = discover_project_runs(project_dir)
    return result(
        "ok",
        project_dir=os.path.abspath(project_dir),
        latest_run=runs[0] if runs else None,
    )


def summarize_latest_run(project_dir: str, top_limit: int = 10) -> dict[str, Any]:
    data = build_summarize_latest_run(project_dir, top_limit=top_limit)
    if data.get("error"):
        return result("error", **data)
    return result("ok", **data)


def strongest_unknown_aps(project_dir: str, limit: int = 25) -> dict[str, Any]:
    data = build_strongest_unknown_aps(project_dir, limit=limit)
    if data.get("error"):
        return result("error", **data)
    return result("ok", **data)


def compare_latest_runs(project_dir: str) -> dict[str, Any]:
    data = build_compare_latest_runs(project_dir)
    if data.get("error"):
        return result("error", **data)
    return result("ok", **data)


def suspicious_handshakes(project_dir: str, limit: int = 25) -> dict[str, Any]:
    data = build_suspicious_handshakes(project_dir, limit=limit)
    if data.get("error"):
        return result("error", **data)
    return result("ok", **data)


def evidence_health(project_dir: str) -> dict[str, Any]:
    data = build_evidence_health(project_dir)
    return result("ok", **data)


def integration_plan() -> dict[str, Any]:
    return result("ok", **planned_integration_surface())


def scan_folder(folder: str, limit: int = 250, include_hidden: bool = False) -> dict[str, Any]:
    candidates = scan_sd_folder(folder, include_hidden=include_hidden)
    by_kind: dict[str, int] = {}
    by_source: dict[str, int] = {}
    recommended = 0
    for cand in candidates:
        by_kind[cand.kind] = by_kind.get(cand.kind, 0) + 1
        by_source[cand.source_app] = by_source.get(cand.source_app, 0) + 1
        if cand.recommended:
            recommended += 1
    limit = max(0, int(limit))
    return result(
        "ok",
        folder=os.path.abspath(folder),
        total=len(candidates),
        recommended=recommended,
        by_kind=by_kind,
        by_source=by_source,
        candidates=candidates[:limit] if limit else candidates,
    )


def analyze_project(
    project_dir: str,
    status_cb: Optional[Callable[[str], None]] = None,
    status_tail_limit: int = 80,
) -> dict[str, Any]:
    logs, pcaps = gather_project_inputs_for_analysis(project_dir)
    events: list[str] = []

    def capture_event(message: str) -> None:
        if len(events) >= status_tail_limit:
            events.pop(0)
        events.append(str(message))
        if status_cb:
            status_cb(str(message))

    if not logs and not pcaps:
        return result(
            "error",
            project_dir=os.path.abspath(project_dir),
            error="No attached logs or PCAPs found for this project.",
        )

    outputs = analyze(logs, pcaps, project_dir, status_cb=capture_event)
    return result(
        "ok",
        project_dir=os.path.abspath(project_dir),
        inputs={"logs": len(logs), "pcaps": len(pcaps)},
        outputs=outputs,
        status_tail=events,
    )


def scrub_project(
    project_dir: str,
    output_dir: Optional[str] = None,
    fuzz_gps: bool = False,
    remove_stations: bool = False,
    remove_pcaps: bool = False,
) -> dict[str, Any]:
    """
    Copy a project vault into output_dir with tokens redacted.

    Removes tokens from the settings table in the DB copy.
    Optionally fuzz GPS coordinates in CSV evidence files (+/- 0.001 deg),
    strip station rows, or remove PCAP files from the copy.
    """
    import random
    import shutil
    import sqlite3
    import csv
    import io

    src = Path(os.path.abspath(project_dir))
    if not src.is_dir():
        return result("error", error=f"Project directory not found: {src}")

    dest_name = output_dir or (str(src) + "_scrubbed")
    dest = Path(dest_name)
    if dest.exists():
        return result("error", error=f"Output directory already exists: {dest}")

    shutil.copytree(str(src), str(dest))

    # Redact tokens in all .db files
    token_keys = ("token", "key", "secret", "credential", "password", "api")
    redacted_keys: list[str] = []
    for db_file in dest.rglob("*.db"):
        try:
            con = sqlite3.connect(str(db_file))
            cur = con.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [r[0] for r in cur.fetchall()]
            if "settings" in tables:
                cur.execute("SELECT key, value FROM settings")
                rows = cur.fetchall()
                for k, v in rows:
                    if any(t in k.lower() for t in token_keys) and v:
                        cur.execute("UPDATE settings SET value=? WHERE key=?", ("[redacted]", k))
                        redacted_keys.append(k)
            con.commit()
            con.close()
        except Exception:
            pass

    # Process CSV evidence files
    removed_pcaps: list[str] = []
    fuzzed_csvs: list[str] = []

    COORD_FIELDS = {"currentlatitude", "currentlongitude", "lat", "lon", "latitude", "longitude"}

    for csv_file in dest.rglob("*.csv"):
        try:
            text = csv_file.read_text(encoding="utf-8", errors="replace")
            reader = csv.DictReader(io.StringIO(text))
            if reader.fieldnames is None:
                continue

            changed = False
            output_rows: list[dict] = []
            for row in reader:
                if remove_stations:
                    # Skip rows with no BSSID (station-only rows)
                    bssid = row.get("MAC", row.get("BSSID", ""))
                    # Stations typically have no SSID
                    ssid = row.get("SSID", row.get("ssid", ""))
                    if not ssid and bssid:
                        changed = True
                        continue
                if fuzz_gps:
                    for field in list(row.keys()):
                        if field.lower() in COORD_FIELDS:
                            try:
                                val = float(row[field])
                                row[field] = str(round(val + random.uniform(-0.001, 0.001), 6))
                                changed = True
                            except (ValueError, TypeError):
                                pass
                output_rows.append(row)

            if changed:
                buf = io.StringIO()
                writer = csv.DictWriter(buf, fieldnames=reader.fieldnames)
                writer.writeheader()
                writer.writerows(output_rows)
                csv_file.write_text(buf.getvalue(), encoding="utf-8")
                fuzzed_csvs.append(str(csv_file.relative_to(dest)))
        except Exception:
            pass

    if remove_pcaps:
        for pcap_file in list(dest.rglob("*.pcap")):
            removed_pcaps.append(str(pcap_file.relative_to(dest)))
            pcap_file.unlink()

    return result(
        "ok",
        source=str(src),
        output=str(dest),
        redacted_settings_keys=redacted_keys,
        fuzzed_csvs=fuzzed_csvs,
        removed_pcaps=removed_pcaps,
    )


def dumps_json(data: dict[str, Any], pretty: bool = True) -> str:
    return json.dumps(_jsonable(data), indent=2 if pretty else None, sort_keys=False)
