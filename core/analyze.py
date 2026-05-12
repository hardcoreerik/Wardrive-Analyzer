"""
Main analysis entry point — orchestrates all modules.
Called by the GUI via: from core import analyze
"""
from __future__ import annotations

import os
from collections import Counter
from typing import Callable, Dict, List, Optional, Set, Tuple

from .constants import NO_DATA, CORE_REVISION
from .helpers import now_str
from .parser_logs import load_wardrive_logs, Sighting
from .parser_pcap import load_pcaps
from .geo import compute_centroid_and_confidence, stability_score, compute_risk
from .writers import (
    write_csv, write_xlsx, write_kml, write_map_html,
    write_pcap_reports, write_summary_html,
)
from .project import create_run_dir, update_manifest, update_project_index


def _emit(cb: Optional[Callable[[str], None]], msg: str) -> None:
    if cb:
        cb(msg)


def _emit_checklist(cb: Optional[Callable[[str], None]], run_dir: str, expected: List[str]) -> None:
    _emit(cb, "")
    _emit(cb, "=== Run Output Checklist ===")
    for rel in expected:
        p = os.path.join(run_dir, rel)
        mark = "[OK]" if os.path.exists(p) else "[MISSING]"
        _emit(cb, f"{mark} {rel}")
    _emit(cb, "=== End Checklist ===")


def analyze(
    wardrive_files: List[str],
    pcap_files: List[str],
    project_dir: str,
    status_cb: Optional[Callable[[str], None]] = None,
) -> dict:
    """
    Public entry point for the GUI.
    Creates a new run folder under project_dir/runs/ and writes all outputs there.
    """
    _emit(status_cb, f"[core {CORE_REVISION}] Project: {project_dir}")

    # 1. Create isolated run folder
    run_dir, run_id = create_run_dir(project_dir)
    _emit(status_cb, f"Run created: {run_id}")

    # 2. Parse GPS logs
    _emit(status_cb, "Parsing wardrive logs (GPS evidence)…")
    sightings_by_mac, logfiles_by_mac = load_wardrive_logs(wardrive_files, status_cb=status_cb)
    raw_sightings = sum(len(v) for v in sightings_by_mac.values())
    all_log_macs: Set[str] = set(sightings_by_mac.keys())

    # 3. Parse PCAPs (parallel, dpkt)
    _emit(status_cb, "Parsing PCAPs (radio evidence, parallel)…")
    (
        ap_bssids, ap_per_pcap, sta_per_pcap,
        ssid_by_bssid, ch_by_ap, rssi_ap,
        ch_by_sta, rssi_sta,
        pcaps_by_ap, pcaps_by_sta,
        eapol_per_pcap, eapol_by_bssid, handshake_conf,
        pcap_status,
    ) = load_pcaps(pcap_files, status_cb=status_cb)

    # 4. Build centroid master table
    centroids: List[dict] = []
    centroid_points: List[Tuple[float, float]] = []

    for mac, sights in sightings_by_mac.items():
        ssids = [s.ssid for s in sights if s.ssid not in (None, "", NO_DATA)]
        top_ssid = Counter(ssids).most_common(1)[0][0] if ssids else NO_DATA

        auths = [s.auth for s in sights if s.auth not in (None, "", NO_DATA)]
        auth_mode = Counter(auths).most_common(1)[0][0] if auths else NO_DATA

        chans = [s.channel for s in sights if s.channel not in (None, "", NO_DATA)]
        chan_mode = Counter(chans).most_common(1)[0][0] if chans else NO_DATA

        rssi_vals = [s.rssi for s in sights if s.rssi is not None]
        best_rssi = max(rssi_vals) if rssi_vals else None
        avg_rssi = round(sum(rssi_vals) / len(rssi_vals), 1) if rssi_vals else None

        clat, clon, conf_m, used_n = compute_centroid_and_confidence(sights)
        if clat is not None and clon is not None:
            centroid_points.append((clat, clon))

        stab = stability_score(conf_m, used_n or 0) if conf_m is not None else 0
        eapol_f = int(eapol_by_bssid.get(mac, 0)) if isinstance(eapol_by_bssid, dict) else 0
        hs_conf = handshake_conf.get(mac, "EAPOL" if eapol_f > 0 else "NONE") if isinstance(handshake_conf, dict) else "NONE"
        risk = compute_risk(auth_mode, top_ssid, best_rssi)

        centroids.append({
            "MAC": mac,
            "TopSSID": top_ssid,
            "SSIDCount": len(set(ssids)),
            "AuthMode": auth_mode,
            "Channel": chan_mode,
            "HandshakeSeen": "Yes" if eapol_f > 0 else "No",
            "HandshakeConfidence": hs_conf,
            "EAPOLFrames": eapol_f,
            "HandshakePCAPFiles": ", ".join(sorted(pcaps_by_ap.get(mac, set()))) if eapol_f > 0 else NO_DATA,
            "Sightings": len(sights),
            "UsedForCentroid": used_n or 0,
            "BestRSSI": best_rssi if best_rssi is not None else NO_DATA,
            "AvgRSSI": avg_rssi if avg_rssi is not None else NO_DATA,
            "CentroidLat": round(clat, 7) if clat is not None else NO_DATA,
            "CentroidLon": round(clon, 7) if clon is not None else NO_DATA,
            "ConfidenceRadiusM": round(conf_m, 1) if conf_m is not None else NO_DATA,
            "Stability": stab,
            "RiskScore": risk,
            "SeenInPCAP": "Yes" if mac in ap_bssids else "No",
            "PCAPFiles": ", ".join(sorted(pcaps_by_ap.get(mac, set()))) or NO_DATA,
            "LogFiles": ", ".join(sorted(logfiles_by_mac.get(mac, set()))) or NO_DATA,
        })

    centroids.sort(key=lambda r: (r.get("RiskScore", 0), r.get("Sightings", 0)), reverse=True)

    # 5. Compute stats
    pcap_unique = len(ap_bssids)
    log_unique = len(all_log_macs)
    overlap = len(all_log_macs & ap_bssids)
    overlap_pct = round((overlap / pcap_unique) * 100, 1) if pcap_unique else 0.0
    overlap_pct_logs = round((overlap / log_unique) * 100, 1) if log_unique else 0.0

    all_rssi = [s.rssi for v in sightings_by_mac.values() for s in v if s.rssi is not None]
    rssi_range = (
        f"{min(all_rssi)} (weak) to {max(all_rssi)} (strong); Avg: {round(sum(all_rssi)/len(all_rssi),1)}"
        if all_rssi else NO_DATA
    )

    if centroid_points:
        lats = [p[0] for p in centroid_points]
        lons = [p[1] for p in centroid_points]
        bounds_str = f"{min(lats):.5f}–{max(lats):.5f} lat, {min(lons):.5f}–{max(lons):.5f} lon"
    else:
        bounds_str = NO_DATA

    stats = {
        "pcap_unique": pcap_unique,
        "log_unique": log_unique,
        "centroid_with_loc": sum(1 for r in centroids if r.get("CentroidLat") not in (NO_DATA, "", None)),
        "raw_sightings": raw_sightings,
        "overlap_text": f"{overlap} ({overlap_pct}% of PCAP BSSIDs; {overlap_pct_logs}% of log MACs)",
        "avg_sightings": round(raw_sightings / log_unique, 2) if log_unique else 0,
        "rssi_range": rssi_range,
        "bounds_str": bounds_str,
    }

    # 6. Write artifacts
    _emit(status_cb, "[+] WR1T1NG: wardrive_master.csv")
    csv_path = write_csv(centroids, run_dir, "wardrive_master.csv")
    _emit(status_cb, "[+] WR1T1NG: wardrive_master.xlsx")
    xlsx_path = write_xlsx(centroids, run_dir, "wardrive_master.xlsx")
    _emit(status_cb, "[+] WR1T1NG: wardrive_map.kml")
    kml_path = write_kml(centroids, run_dir)
    _emit(status_cb, "[+] R3ND3R1NG: map.html (heatmap + route)")
    map_path = write_map_html(centroids, sightings_by_mac, run_dir)
    _emit(status_cb, "[*] G3N3R4T1NG PCAP R3P0RTS…")
    pcap_arts = write_pcap_reports(
        outdir=run_dir,
        ap_bssids=ap_bssids,
        ap_per_pcap_counts=ap_per_pcap,
        sta_per_pcap_counts=sta_per_pcap,
        ssid_counts_by_bssid=ssid_by_bssid,
        ch_counts_by_ap=ch_by_ap,
        best_rssi_by_ap=rssi_ap,
        ch_counts_by_sta=ch_by_sta,
        best_rssi_by_sta=rssi_sta,
        pcaps_by_ap=pcaps_by_ap,
        pcaps_by_sta=pcaps_by_sta,
        eapol_per_pcap=eapol_per_pcap,
        eapol_by_bssid=eapol_by_bssid,
        handshake_conf_by_bssid=handshake_conf,
        all_log_macs=all_log_macs,
        status=pcap_status,
    )
    _emit(status_cb, "[+] R3ND3R1NG: summary.html")
    summary_path = write_summary_html(centroids, run_dir, pcap_status, stats)

    results = {
        "project_dir": project_dir,
        "run_dir": run_dir,
        "run_id": run_id,
        "csv": csv_path,
        "xlsx": xlsx_path or NO_DATA,
        "kml": kml_path,
        "map": map_path,
        "summary": summary_path,
        **pcap_arts,
    }

    # 7. Update manifest + project index
    update_manifest(project_dir, run_id, results)
    results["project_index"] = update_project_index(project_dir)

    _emit_checklist(status_cb, run_dir, [
        "wardrive_master.csv", "wardrive_master.xlsx", "wardrive_map.kml",
        "map.html", "summary.html", "pcap_summary.html",
        "pcap_bssid_master.csv", "pcap_bssid_master.xlsx", "pcap_per_file_summary.csv",
    ])

    return results
