from __future__ import annotations

import csv
import os
from pathlib import Path
from typing import Any, Iterable

from project_vault import compare_run_masters, discover_project_runs, list_project_evidence_detailed


UNKNOWN_VALUES = {"", "NO DATA", "<HIDDEN>", "UNKNOWN", "N/A", "NONE"}
HANDSHAKE_RANK = {"4WAY": 4, "PARTIAL": 3, "EAPOL": 2, "NONE": 0, "NO DATA": 0, "": 0}


def _read_csv_rows(path: str) -> list[dict[str, str]]:
    if not path or not os.path.exists(path):
        return []
    with open(path, "r", newline="", encoding="utf-8-sig") as f:
        return [{str(k): str(v) for k, v in row.items()} for row in csv.DictReader(f)]


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(float(str(value).strip()))
    except (TypeError, ValueError):
        return default


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return default


def _limit(value: int, default: int = 25) -> int:
    value = _as_int(value, default)
    return max(1, min(value, 250))


def _is_unknown(value: Any) -> bool:
    text = str(value or "").strip()
    if text.upper() in UNKNOWN_VALUES:
        return True
    return text.startswith("<") and text.endswith(">")


def _auth_is_open(value: Any) -> bool:
    text = str(value or "").lower()
    return text in {"open", "opn"} or "open" in text or "no privacy" in text


def _risk_tier(score: Any) -> str:
    risk = _as_int(score)
    if risk >= 80:
        return "critical"
    if risk >= 60:
        return "high"
    if risk >= 35:
        return "medium"
    return "low"


def _interesting_ap(row: dict[str, str]) -> dict[str, Any]:
    return {
        "mac": row.get("MAC") or row.get("BSSID") or "",
        "ssid": row.get("TopSSID") or row.get("SSID(s)") or row.get("SSID") or "",
        "auth": row.get("AuthMode") or row.get("Auth") or "",
        "channel": row.get("Channel") or "",
        "best_rssi": _as_int(row.get("BestRSSI"), -999),
        "risk_score": _as_int(row.get("RiskScore")),
        "handshake_seen": row.get("HandshakeSeen") or "",
        "handshake_confidence": row.get("HandshakeConfidence") or "",
        "eapol_frames": _as_int(row.get("EAPOLFrames")),
        "pcap_files": row.get("PCAPFiles") or row.get("HandshakePCAPFiles") or "",
        "sightings": _as_int(row.get("Sightings")),
        "used_for_centroid": _as_int(row.get("UsedForCentroid")),
        "active_days": _as_int(row.get("ActiveDays")),
        "source_file_count": _as_int(row.get("SourceFileCount")),
        "multi_day_seen": row.get("MultiDaySeen") or "",
        "location_quality": row.get("LocationQuality") or "",
        "confidence_radius_m": _as_float(row.get("ConfidenceRadiusM")),
        "first_seen": row.get("FirstSeen") or "",
        "last_seen": row.get("LastSeen") or "",
    }


def _runs_with_output(project_dir: str, filename: str) -> list[dict[str, Any]]:
    runs = discover_project_runs(project_dir)
    return [run for run in runs if str((run.get("outputs") or {}).get(filename) or "")]


def _csv_path(run: dict[str, Any], filename: str) -> str:
    return str((run.get("outputs") or {}).get(filename) or "")


def _summarize_rows(rows: Iterable[dict[str, str]]) -> dict[str, Any]:
    risk_tiers = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    auth_counts: dict[str, int] = {}
    hidden_or_unknown = 0
    open_networks = 0
    handshake_aps = 0
    located = 0
    repeated = 0
    multi_file = 0
    multi_day = 0
    location_quality: dict[str, int] = {}
    total = 0

    for row in rows:
        total += 1
        risk_tiers[_risk_tier(row.get("RiskScore"))] += 1
        auth = (row.get("AuthMode") or row.get("Auth") or "No Data").strip() or "No Data"
        auth_counts[auth] = auth_counts.get(auth, 0) + 1
        if _is_unknown(row.get("TopSSID") or row.get("SSID")):
            hidden_or_unknown += 1
        if _auth_is_open(auth):
            open_networks += 1
        if str(row.get("HandshakeSeen") or "").strip().lower() == "yes" or _as_int(row.get("EAPOLFrames")) > 0:
            handshake_aps += 1
        if str(row.get("CentroidLat") or "").strip() and str(row.get("CentroidLon") or "").strip():
            located += 1
        if _as_int(row.get("Sightings")) > 1:
            repeated += 1
        if _as_int(row.get("SourceFileCount")) > 1 or str(row.get("RepeatedAcrossFiles") or "").strip().lower() == "yes":
            multi_file += 1
        if _as_int(row.get("ActiveDays")) > 1 or str(row.get("MultiDaySeen") or "").strip().lower() == "yes":
            multi_day += 1
        quality = (row.get("LocationQuality") or "Unknown").strip() or "Unknown"
        location_quality[quality] = location_quality.get(quality, 0) + 1

    return {
        "total_aps": total,
        "located_aps": located,
        "hidden_or_unknown_ssids": hidden_or_unknown,
        "open_networks": open_networks,
        "handshake_aps": handshake_aps,
        "repeated_aps": repeated,
        "multi_file_aps": multi_file,
        "multi_day_aps": multi_day,
        "location_quality": location_quality,
        "risk_tiers": risk_tiers,
        "auth_counts": auth_counts,
    }


def _trim_comparison(comparison: dict[str, Any], sample_limit: int = 50) -> dict[str, Any]:
    trimmed = dict(comparison)
    for key in ("added", "missing", "changed"):
        values = list(trimmed.get(key) or [])
        trimmed[key] = values[:sample_limit]
        trimmed[f"{key}_sample_limit"] = sample_limit
        trimmed[f"{key}_truncated"] = len(values) > sample_limit
    return trimmed


def summarize_latest_run(project_dir: str, top_limit: int = 10) -> dict[str, Any]:
    runs = _runs_with_output(project_dir, "wardrive_master.csv")
    if not runs:
        return {"error": "No run with wardrive_master.csv was found."}

    latest = runs[0]
    previous = runs[1] if len(runs) > 1 else None
    rows = _read_csv_rows(_csv_path(latest, "wardrive_master.csv"))
    top_limit = _limit(top_limit, 10)
    top_risks = sorted(
        (_interesting_ap(row) for row in rows),
        key=lambda row: (row["risk_score"], row["best_rssi"]),
        reverse=True,
    )[:top_limit]
    repeat_candidates = sorted(
        (_interesting_ap(row) for row in rows if _as_int(row.get("Sightings")) > 1),
        key=lambda row: (
            row["active_days"],
            row["source_file_count"],
            row["sightings"],
            -row["confidence_radius_m"],
        ),
        reverse=True,
    )[:top_limit]

    change_summary = None
    if previous:
        change_summary = _trim_comparison(
            compare_run_masters(
                _csv_path(latest, "wardrive_master.csv"),
                _csv_path(previous, "wardrive_master.csv"),
            )
        )

    return {
        "project_dir": os.path.abspath(project_dir),
        "run": {
            "run_id": latest.get("run_id"),
            "run_dir": latest.get("run_dir"),
            "modified": latest.get("modified"),
        },
        "previous_run": {
            "run_id": previous.get("run_id"),
            "run_dir": previous.get("run_dir"),
            "modified": previous.get("modified"),
        }
        if previous
        else None,
        "summary": _summarize_rows(rows),
        "top_risks": top_risks,
        "repeat_location_candidates": repeat_candidates,
        "what_changed_since_last_run": change_summary,
    }


def strongest_unknown_aps(project_dir: str, limit: int = 25) -> dict[str, Any]:
    runs = _runs_with_output(project_dir, "wardrive_master.csv")
    if not runs:
        return {"error": "No run with wardrive_master.csv was found."}

    latest = runs[0]
    rows = _read_csv_rows(_csv_path(latest, "wardrive_master.csv"))
    unknown = [
        _interesting_ap(row)
        for row in rows
        if _is_unknown(row.get("TopSSID") or row.get("SSID")) or _is_unknown(row.get("AuthMode") or row.get("Auth"))
    ]
    unknown.sort(key=lambda row: (row["best_rssi"], row["risk_score"]), reverse=True)
    return {
        "project_dir": os.path.abspath(project_dir),
        "run_id": latest.get("run_id"),
        "total_unknown": len(unknown),
        "aps": unknown[: _limit(limit)],
    }


def compare_latest_runs(project_dir: str) -> dict[str, Any]:
    runs = _runs_with_output(project_dir, "wardrive_master.csv")
    if len(runs) < 2:
        return {"error": "At least two runs with wardrive_master.csv are required."}

    latest, previous = runs[0], runs[1]
    comparison = _trim_comparison(
        compare_run_masters(
            _csv_path(latest, "wardrive_master.csv"),
            _csv_path(previous, "wardrive_master.csv"),
        )
    )
    return {
        "project_dir": os.path.abspath(project_dir),
        "latest_run": {"run_id": latest.get("run_id"), "run_dir": latest.get("run_dir"), "modified": latest.get("modified")},
        "previous_run": {"run_id": previous.get("run_id"), "run_dir": previous.get("run_dir"), "modified": previous.get("modified")},
        "comparison": comparison,
    }


def suspicious_handshakes(project_dir: str, limit: int = 25) -> dict[str, Any]:
    runs = _runs_with_output(project_dir, "pcap_bssid_master.csv")
    if not runs:
        return {"error": "No run with pcap_bssid_master.csv was found."}

    latest = runs[0]
    rows = _read_csv_rows(_csv_path(latest, "pcap_bssid_master.csv"))
    flagged: list[dict[str, Any]] = []
    for row in rows:
        confidence = str(row.get("HandshakeConfidence") or "").strip().upper()
        eapol_frames = _as_int(row.get("EAPOLFrames"))
        if str(row.get("HandshakeSeen") or "").strip().lower() == "yes" or eapol_frames > 0 or confidence not in {"", "NONE", "NO DATA"}:
            flagged.append(
                {
                    "bssid": row.get("BSSID") or "",
                    "ssids": row.get("SSID(s)") or "",
                    "frames": _as_int(row.get("Frames")),
                    "handshake_seen": row.get("HandshakeSeen") or "",
                    "handshake_confidence": confidence or "NONE",
                    "eapol_frames": eapol_frames,
                    "handshake_pcap_files": row.get("HandshakePCAPFiles") or "",
                    "pcap_files": row.get("PCAPFiles") or "",
                    "matched_in_logs": row.get("MatchedInLogs") or "",
                }
            )

    flagged.sort(
        key=lambda row: (
            HANDSHAKE_RANK.get(str(row["handshake_confidence"]).upper(), 1),
            _as_int(row["eapol_frames"]),
            _as_int(row["frames"]),
        ),
        reverse=True,
    )
    return {
        "project_dir": os.path.abspath(project_dir),
        "run_id": latest.get("run_id"),
        "total_flagged": len(flagged),
        "handshakes": flagged[: _limit(limit)],
    }


def evidence_health(project_dir: str) -> dict[str, Any]:
    runs = discover_project_runs(project_dir)
    latest = runs[0] if runs else None
    evidence = list_project_evidence_detailed(project_dir)
    seen: dict[tuple[str, str], int] = {}
    duplicates: list[dict[str, Any]] = []
    missing_files: list[dict[str, str]] = []
    for row in evidence:
        source_path = str(row.get("source_path") or row.get("path") or "")
        sha256 = str(row.get("sha256") or "")
        key = (sha256, os.path.basename(source_path).lower())
        if key in seen:
            duplicates.append({"path": source_path, "sha256": sha256})
        seen[key] = seen.get(key, 0) + 1
        if source_path and not os.path.exists(source_path):
            missing_files.append({"path": source_path, "reason": "source path no longer exists"})

    latest_missing = list(latest.get("missing") or []) if latest else []
    per_file_warnings: list[dict[str, Any]] = []
    if latest:
        per_csv = _csv_path(latest, "pcap_per_file_summary.csv")
        for row in _read_csv_rows(per_csv):
            ap_frames = _as_int(row.get("AP_Frames"))
            sta_frames = _as_int(row.get("Station_Frames"))
            eapol = _as_int(row.get("EAPOL_Frames"))
            if ap_frames == 0 and sta_frames == 0 and eapol == 0:
                per_file_warnings.append({"pcap": row.get("PCAP") or "", "warning": "no decoded AP, station, or EAPOL frames"})

    return {
        "project_dir": os.path.abspath(project_dir),
        "evidence_rows": len(evidence),
        "duplicate_warnings": duplicates[:50],
        "missing_source_files": missing_files[:50],
        "latest_run": {
            "run_id": latest.get("run_id"),
            "run_dir": latest.get("run_dir"),
            "missing_outputs": latest_missing,
        }
        if latest
        else None,
        "pcap_health_warnings": per_file_warnings[:50],
        "notes": [
            "SSID sanitation is applied during CSV/XLSX writing and PCAP parsing.",
            "Corrupt PCAP detection is reported here when decoded packet summaries are empty; deeper parser errors are captured in error_reports.",
        ],
    }


def planned_integration_surface() -> dict[str, Any]:
    return {
        "import_adapters": ["kismet_sqlite", "kismet_csv", "wigle_csv", "airodump_csv", "wireshark_pcap_metadata"],
        "future_device_types": ["wifi_ap", "wifi_station", "bluetooth_ble_when_adapter_exists"],
        "ai_bridge_tools": [
            "summarize_latest_run",
            "strongest_unknown_aps",
            "compare_latest_runs",
            "suspicious_handshakes",
            "evidence_health",
        ],
        "map_upgrades": ["run_comparison_overlay", "confidence_circles", "auth_risk_vendor_filters", "floorplan_heatmaps"],
        "global_wireless_databases": ["wigle_optional_enrichment_cache"],
    }
