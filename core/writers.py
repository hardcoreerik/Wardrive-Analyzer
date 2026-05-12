"""
Artifact writers: CSV, XLSX, KML, HTML (map + summary + PCAP report).

Map features:
  - Centroid markers with popups
  - Confidence circles (toggle layer)
  - Signal heatmap (Leaflet.heat, toggle layer)
  - Drive route polyline (toggle layer)
  - Bundled Leaflet with CDN fallback
"""
from __future__ import annotations

import csv
import math
import os
import re
import sys
from collections import Counter
from html import escape
from typing import Dict, List, Optional, Set, Tuple

from .constants import (
    NO_DATA, KML_CIRCLE_POINTS,
    LEAFLET_CSS_LOCAL, LEAFLET_JS_LOCAL,
    LEAFLET_CSS_CDN, LEAFLET_JS_CDN,
)
from .helpers import (
    now_str, oui_key, is_locally_administered, json_str, json_arr,
    resource_path,
)
from .parser_logs import Sighting

_EXCEL_ILLEGAL_RE = re.compile(r"[\x00-\x08\x0B-\x0C\x0E-\x1F]")
_PRINTABLE_CONTROL_RE = re.compile(r"[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F-\x9F]")
_EXCEL_MAX_CELL_CHARS = 32767


def clean_report_value(value, max_chars: int = _EXCEL_MAX_CELL_CHARS):
    """Return a report-safe scalar for CSV/XLSX/HTML writers."""
    if value is None:
        return NO_DATA
    if isinstance(value, (int, float, bool)):
        return value

    text = str(value)
    if not text:
        return NO_DATA

    text = _PRINTABLE_CONTROL_RE.sub("", text)
    text = _EXCEL_ILLEGAL_RE.sub("", text)
    text = text.replace("\ufffd", "?")
    text = text.strip()
    if len(text) > max_chars:
        text = text[: max_chars - 20] + "... [truncated]"
    return text or NO_DATA


def clean_report_row(row: dict) -> dict:
    return {k: clean_report_value(v) for k, v in row.items()}


# ---------------------------------------------------------------------------
# OUI lookup
# ---------------------------------------------------------------------------

def load_oui_db() -> Tuple[Dict[str, str], str, int]:
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    candidates = [
        os.path.join(base, "oui.csv"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "oui.csv"),
    ]
    for p in candidates:
        p = os.path.normpath(p)
        if not os.path.exists(p):
            continue
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                reader = csv.reader(f)
                rows = list(reader)
            if not rows:
                return {}, p, 0

            header = [h.strip().lower() for h in rows[0]]
            m: Dict[str, str] = {}

            if "assignment" in header:
                ia = header.index("assignment")
                iname = header.index("organization name") if "organization name" in header else 1
                for r in rows[1:]:
                    if len(r) <= max(ia, iname):
                        continue
                    raw = r[ia].strip().upper().replace("-", ":")
                    if re.fullmatch(r"[0-9A-F]{6}", raw):
                        raw = ":".join([raw[i: i + 2] for i in range(0, 6, 2)])
                    if re.fullmatch(r"[0-9A-F]{2}(:[0-9A-F]{2}){2}", raw):
                        m[raw] = r[iname].strip() or NO_DATA
                return m, p, len(m)
        except Exception:
            return {}, p, 0
    return {}, NO_DATA, 0


def vendor_for(mac: str, oui_db: Dict[str, str]) -> str:
    k = oui_key(mac)
    return oui_db.get(k, NO_DATA) if k else NO_DATA


def category_guess(role: str, vendor: str, locally_admin: bool) -> str:
    if role == "AP":
        v = vendor.upper()
        if any(x in v for x in ("NETGEAR", "TP-LINK", "ARCADYAN", "CISCO", "UBIQUITI")):
            return "Access Point/Router (guess)"
        return "Access Point (observed role)"
    if locally_admin:
        return "Unknown (randomized MAC)"
    v = vendor.upper()
    if "APPLE" in v:
        return "Phone/Tablet (guess)"
    if "SAMSUNG" in v:
        return "Phone/Tablet (guess)"
    if any(x in v for x in ("MICROSOFT", "INTEL", "DELL", "LENOVO", "HP")):
        return "PC/Laptop (guess)"
    return "Wireless client (unknown type)"


def ssid_display(ssid_raw: str) -> str:
    s = clean_report_value(ssid_raw, max_chars=512) if ssid_raw not in (None, "", NO_DATA) else ""
    if not s:
        return "ASCII: <MISSING>"
    if re.fullmatch(r"[0-9A-Fa-f]+", s) and len(s) % 2 == 0 and len(s) >= 2:
        try:
            ascii_guess = bytes.fromhex(s).decode("utf-8", errors="ignore").strip() or "<MISSING>"
            return f"ASCII: {ascii_guess} | HEX: {s.lower()}"
        except Exception:
            return f"ASCII: <MISSING> | HEX: {s.lower()}"
    try:
        hx = s.encode("utf-8", errors="ignore").hex()
        return f"ASCII: {s} | HEX: {hx}"
    except Exception:
        return f"ASCII: {s}"


def _to_int(value, default: int = 0) -> int:
    try:
        return int(float(str(value).strip()))
    except (TypeError, ValueError):
        return default


def _to_float(value, default: float = 0.0) -> float:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return default


def _top_repeated_rows(centroids: List[dict], limit: int = 25) -> List[Tuple]:
    repeated = [
        c for c in centroids
        if _to_int(c.get("Sightings")) > 1 or c.get("RepeatedAcrossFiles") == "Yes" or c.get("MultiDaySeen") == "Yes"
    ]
    repeated.sort(
        key=lambda c: (
            _to_int(c.get("ActiveDays")),
            _to_int(c.get("SourceFileCount")),
            _to_int(c.get("Sightings")),
            _to_int(c.get("Stability")),
        ),
        reverse=True,
    )
    rows = []
    for c in repeated[:limit]:
        rows.append((
            c.get("MAC", NO_DATA),
            c.get("TopSSID", NO_DATA),
            c.get("Sightings", NO_DATA),
            c.get("UsedForCentroid", NO_DATA),
            c.get("ActiveDays", NO_DATA),
            c.get("SourceFileCount", NO_DATA),
            c.get("MultiDaySeen", NO_DATA),
            c.get("ConfidenceRadiusM", NO_DATA),
            c.get("LocationQuality", NO_DATA),
            c.get("FirstSeen", NO_DATA),
            c.get("LastSeen", NO_DATA),
        ))
    return rows


def _best_location_rows(centroids: List[dict], limit: int = 25) -> List[Tuple]:
    located = [c for c in centroids if c.get("CentroidLat") not in (NO_DATA, "", None)]
    located.sort(
        key=lambda c: (
            {"High": 3, "Medium": 2, "Low": 1}.get(str(c.get("LocationQuality")), 0),
            _to_int(c.get("Stability")),
            -_to_float(c.get("ConfidenceRadiusM"), 999999.0),
            _to_int(c.get("UsedForCentroid")),
        ),
        reverse=True,
    )
    rows = []
    for c in located[:limit]:
        rows.append((
            c.get("MAC", NO_DATA),
            c.get("TopSSID", NO_DATA),
            c.get("LocationQuality", NO_DATA),
            c.get("Stability", NO_DATA),
            c.get("ConfidenceRadiusM", NO_DATA),
            c.get("UsedForCentroid", NO_DATA),
            c.get("Sightings", NO_DATA),
            c.get("CentroidLat", NO_DATA),
            c.get("CentroidLon", NO_DATA),
        ))
    return rows


# ---------------------------------------------------------------------------
# CSV / XLSX
# ---------------------------------------------------------------------------

def write_csv(rows: List[dict], outdir: str, filename: str) -> str:
    path = os.path.join(outdir, filename)
    headers = list(rows[0].keys()) if rows else ["MAC"]
    safe_rows = [clean_report_row(r) for r in rows] if rows else []
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, headers)
        w.writeheader()
        if safe_rows:
            w.writerows(safe_rows)
    return path


def write_xlsx(rows: List[dict], outdir: str, filename: str) -> Optional[str]:
    try:
        from openpyxl import Workbook  # type: ignore
        from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE  # type: ignore
    except Exception:
        return None
    path = os.path.join(outdir, filename)
    wb = Workbook()
    ws = wb.active
    ws.title = "Data"
    headers = list(rows[0].keys()) if rows else ["MAC"]
    ws.append(headers)
    for r in rows:
        safe_values = []
        for h in headers:
            value = clean_report_value(r.get(h, NO_DATA))
            if isinstance(value, str):
                value = ILLEGAL_CHARACTERS_RE.sub("", value)
            safe_values.append(value)
        ws.append(safe_values)
    ws.freeze_panes = "A2"
    wb.save(path)
    return path


# ---------------------------------------------------------------------------
# KML
# ---------------------------------------------------------------------------

def _kml_circle(lat: float, lon: float, radius_m: float) -> str:
    coords = []
    R = 6_371_000.0
    lat1, lon1 = math.radians(lat), math.radians(lon)
    for i in range(KML_CIRCLE_POINTS + 1):
        brg = math.radians((360.0 / KML_CIRCLE_POINTS) * i)
        d = radius_m / R
        lat2 = math.asin(math.sin(lat1) * math.cos(d) + math.cos(lat1) * math.sin(d) * math.cos(brg))
        lon2 = lon1 + math.atan2(
            math.sin(brg) * math.sin(d) * math.cos(lat1),
            math.cos(d) - math.sin(lat1) * math.sin(lat2),
        )
        coords.append(f"{math.degrees(lon2)},{math.degrees(lat2)},0")
    return " ".join(coords)


def write_kml(centroids: List[dict], outdir: str) -> str:
    path = os.path.join(outdir, "wardrive_map.kml")
    placemarks = []
    for c in centroids:
        if c.get("CentroidLat") in (NO_DATA, "", None):
            continue
        lat, lon = float(c["CentroidLat"]), float(c["CentroidLon"])
        name = escape(c.get("TopSSID", NO_DATA))
        desc = (
            f"MAC: {escape(c['MAC'])}<br>"
            f"Security: {escape(c.get('AuthMode', NO_DATA))}<br>"
            f"Obs: {escape(str(c.get('Sightings', NO_DATA)))}<br>"
            f"Used for centroid: {escape(str(c.get('UsedForCentroid', NO_DATA)))}<br>"
            f"Active days: {escape(str(c.get('ActiveDays', NO_DATA)))}<br>"
            f"Confidence (m): {escape(str(c.get('ConfidenceRadiusM', NO_DATA)))}<br>"
            f"Location quality: {escape(str(c.get('LocationQuality', NO_DATA)))}<br>"
            f"Seen in PCAP: {escape(c.get('SeenInPCAP', NO_DATA))}"
        )
        placemarks.append(
            f"<Placemark><name>{name}</name>"
            f"<description><![CDATA[{desc}]]></description>"
            f"<Point><coordinates>{lon},{lat},0</coordinates></Point></Placemark>"
        )
        try:
            conf_m = float(c.get("ConfidenceRadiusM", 0))
        except Exception:
            conf_m = 0.0
        if conf_m > 0:
            ring = _kml_circle(lat, lon, conf_m)
            placemarks.append(
                "<Placemark>"
                f"<name>{name} (confidence)</name>"
                "<Style><LineStyle><color>ff00ffff</color><width>1</width></LineStyle>"
                "<PolyStyle><color>2200ffff</color></PolyStyle></Style>"
                "<Polygon><outerBoundaryIs><LinearRing>"
                f"<coordinates>{ring}</coordinates>"
                "</LinearRing></outerBoundaryIs></Polygon></Placemark>"
            )
    kml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<kml xmlns="http://www.opengis.net/kml/2.2"><Document>'
        "<name>Wardrive Centroids</name>"
        + "".join(placemarks) + "</Document></kml>"
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(kml)
    return path


# ---------------------------------------------------------------------------
# Map HTML (offline Leaflet + heatmap + route)
# ---------------------------------------------------------------------------

def _leaflet_assets(outdir: str) -> Tuple[str, str]:
    """
    Copy bundled Leaflet into the run folder so maps work offline.
    Returns (css_ref, js_ref) — relative paths for the HTML.
    """
    import shutil

    # Bundled location (dev: assets/leaflet, PyInstaller: _MEIPASS/assets/leaflet)
    src_dir = resource_path("assets", "leaflet")
    dst_dir = os.path.join(outdir, "leaflet")

    files = ["leaflet.css", "leaflet.js", "leaflet-heat.js"]
    if os.path.isdir(src_dir):
        os.makedirs(dst_dir, exist_ok=True)
        for fn in files:
            src = os.path.join(src_dir, fn)
            if os.path.exists(src):
                shutil.copy2(src, os.path.join(dst_dir, fn))

    css_out = os.path.join(dst_dir, "leaflet.css")
    js_out = os.path.join(dst_dir, "leaflet.js")
    if os.path.exists(css_out) and os.path.exists(js_out):
        return "leaflet/leaflet.css", "leaflet/leaflet.js"
    # CDN fallback
    return LEAFLET_CSS_CDN, LEAFLET_JS_CDN


def write_map_html(
    centroids: List[dict],
    sightings_by_mac: Dict[str, List[Sighting]],
    outdir: str,
    circles_enabled_default: bool = False,
) -> str:
    path = os.path.join(outdir, "map.html")
    css_ref, js_ref = _leaflet_assets(outdir)

    pts = [c for c in centroids if c.get("CentroidLat") not in (NO_DATA, "", None)]

    markers_js: List[str] = []
    circles_js: List[str] = []
    bounds_js: List[str] = []
    heat_pts: List[str] = []   # [lat, lon, intensity]
    route_pts: List[str] = []  # drive path ordered by first_seen

    # Build heatmap points from all raw sightings
    all_sightings: List[Sighting] = []
    for sl in sightings_by_mac.values():
        all_sightings.extend(sl)

    # Sort by first_seen for route
    def _ts_key(s: Sighting) -> str:
        return s.first_seen or ""
    all_sightings.sort(key=_ts_key)

    seen_route: set = set()
    for s in all_sightings:
        if s.lat is not None and s.lon is not None:
            intensity = max(0.1, min(1.0, 1.0 - (abs(s.rssi or -90) - 30) / 80)) if s.rssi else 0.3
            heat_pts.append(f"[{s.lat},{s.lon},{intensity:.2f}]")
            coord_key = (round(s.lat, 5), round(s.lon, 5))
            if coord_key not in seen_route:
                seen_route.add(coord_key)
                route_pts.append(f"[{s.lat},{s.lon}]")

    for c in pts:
        lat, lon = float(c["CentroidLat"]), float(c["CentroidLon"])
        bounds_js.append(f"[{lat},{lon}]")
        popup = (
            f"<b>{escape(c.get('TopSSID', NO_DATA))}</b><br>"
            f"MAC: {escape(c['MAC'])}<br>"
            f"Security: {escape(c.get('AuthMode', NO_DATA))}<br>"
            f"Obs: {escape(str(c.get('Sightings', NO_DATA)))}<br>"
            f"Used for centroid: {escape(str(c.get('UsedForCentroid', NO_DATA)))}<br>"
            f"Active days: {escape(str(c.get('ActiveDays', NO_DATA)))}<br>"
            f"Source files: {escape(str(c.get('SourceFileCount', NO_DATA)))}<br>"
            f"Confidence (m): {escape(str(c.get('ConfidenceRadiusM', NO_DATA)))}<br>"
            f"Stability: {escape(str(c.get('Stability', NO_DATA)))}<br>"
            f"Location quality: {escape(str(c.get('LocationQuality', NO_DATA)))}<br>"
            f"First seen: {escape(str(c.get('FirstSeen', NO_DATA)))}<br>"
            f"Last seen: {escape(str(c.get('LastSeen', NO_DATA)))}<br>"
            f"Risk: {escape(str(c.get('RiskScore', NO_DATA)))}<br>"
            f"Seen in PCAP: {escape(c.get('SeenInPCAP', NO_DATA))}"
        )
        markers_js.append(
            f"L.marker([{lat},{lon}]).bindPopup({json_str(popup)}).addTo(layerCentroids);"
        )
        try:
            conf_m = float(c.get("ConfidenceRadiusM", 0))
        except Exception:
            conf_m = 0.0
        if conf_m > 0:
            circles_js.append(
                f"L.circle([{lat},{lon}], {{radius:{conf_m}, weight:1, fillOpacity:0.12, renderer:canvasRenderer}}).addTo(layerConfidence);"
            )

    conf_add = "layerConfidence.addTo(map);" if circles_enabled_default else ""

    # Leaflet.heat — prefer bundled, fall back to CDN
    heat_local = os.path.join(outdir, "leaflet", "leaflet-heat.js")
    heat_ref = "leaflet/leaflet-heat.js" if os.path.exists(heat_local) else "https://unpkg.com/leaflet.heat@0.2.0/dist/leaflet-heat.js"

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8"/>
<title>Wardrive Map</title>
<link rel="stylesheet" href="{css_ref}"/>
<script src="{js_ref}"></script>
<link rel="stylesheet" href="https://unpkg.com/leaflet.markercluster@1.5.3/dist/MarkerCluster.css"/>
<link rel="stylesheet" href="https://unpkg.com/leaflet.markercluster@1.5.3/dist/MarkerCluster.Default.css"/>
<script src="https://unpkg.com/leaflet.markercluster@1.5.3/dist/leaflet.markercluster.js"></script>
<script src="{heat_ref}"></script>
<style>
  body {{ margin:0; background:#050607; color:#00ff88; font-family:Consolas,monospace; }}
  #map {{ height:100vh; width:100vw; }}
</style>
</head>
<body>
<div id="map"></div>
<script>
(function() {{
  try {{
    var map = L.map('map');
    L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
      maxZoom: 19, attribution: '&copy; OpenStreetMap contributors'
    }}).addTo(map);

    var canvasRenderer = L.canvas({{padding: 0.5}});
    var layerCentroids  = L.markerClusterGroup({{maxClusterRadius:60, disableClusteringAtZoom:17}});
    layerCentroids.addTo(map);
    var layerConfidence = L.layerGroup();
    {conf_add}

    {''.join(markers_js)}
    {''.join(circles_js)}

    // Heatmap layer
    var heatData = {json_arr(heat_pts[:5000])};
    var layerHeat = L.heatLayer(heatData, {{radius:18, blur:15, maxZoom:17}});

    // Drive route layer
    var routeData = {json_arr(route_pts[:10000])};
    var layerRoute = L.polyline(routeData, {{color:'#00ffcc', weight:2, opacity:0.6}});

    L.control.layers(null, {{
      "AP Centroids": layerCentroids,
      "Confidence Circles": layerConfidence,
      "Signal Heatmap": layerHeat,
      "Drive Route": layerRoute
    }}, {{collapsed:false}}).addTo(map);

    var pts = {json_arr(bounds_js)};
    if (pts.length > 0) {{
      map.fitBounds(L.latLngBounds(pts).pad(0.15));
    }} else if (routeData.length > 0) {{
      map.fitBounds(L.latLngBounds(routeData).pad(0.10));
    }} else {{
      map.setView([0,0], 2);
    }}
  }} catch(e) {{
    console.error(e);
    document.body.innerHTML = "<pre style='color:#ff5577;padding:20px'>Map error: "+e+"</pre>";
  }}
}})();
</script>
</body>
</html>
"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path


# ---------------------------------------------------------------------------
# HTML table helper
# ---------------------------------------------------------------------------

def _html_table(headers: List[str], rows: List[Tuple]) -> str:
    th = "".join(f"<th>{escape(str(h))}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{escape(str(x))}</td>" for x in r) + "</tr>"
        for r in rows
    )
    return f"<table><tr>{th}</tr>{body}</table>"


# ---------------------------------------------------------------------------
# PCAP report
# ---------------------------------------------------------------------------

def write_pcap_reports(
    outdir: str,
    ap_bssids: Set[str],
    ap_per_pcap_counts: Dict[str, Counter],
    sta_per_pcap_counts: Dict[str, Counter],
    ssid_counts_by_bssid: Dict[str, Counter],
    ch_counts_by_ap: Dict[str, Counter],
    best_rssi_by_ap: Dict[str, int],
    ch_counts_by_sta: Dict[str, Counter],
    best_rssi_by_sta: Dict[str, int],
    pcaps_by_ap: Dict[str, Set[str]],
    pcaps_by_sta: Dict[str, Set[str]],
    eapol_per_pcap: Dict[str, int],
    eapol_by_bssid: Dict[str, int],
    handshake_conf_by_bssid: Dict[str, str],
    all_log_macs: Set[str],
    status: str,
) -> dict:
    oui_db, oui_src, oui_entries = load_oui_db()

    master_rows: List[dict] = []
    for bssid in sorted(ap_bssids):
        ssid_ctr = ssid_counts_by_bssid.get(bssid, Counter())
        ssids_csv = ", ".join(s for s, _ in ssid_ctr.most_common()) or NO_DATA
        frames = sum(c.get(bssid, 0) for c in ap_per_pcap_counts.values())
        eapol_frames = int(eapol_by_bssid.get(bssid, 0))
        hs_conf = handshake_conf_by_bssid.get(bssid, "EAPOL" if eapol_frames > 0 else "NONE")
        master_rows.append({
            "BSSID": bssid,
            "SSID(s)": ssids_csv,
            "Frames": frames,
            "HandshakeSeen": "Yes" if eapol_frames > 0 else "No",
            "HandshakeConfidence": hs_conf,
            "EAPOLFrames": eapol_frames,
            "HandshakePCAPFiles": ", ".join(sorted(pcaps_by_ap.get(bssid, set()))) if eapol_frames > 0 else NO_DATA,
            "PCAPFiles": ", ".join(sorted(pcaps_by_ap.get(bssid, set()))) or NO_DATA,
            "MatchedInLogs": "Yes" if bssid in all_log_macs else "No",
        })
    master_rows.sort(key=lambda r: int(r.get("Frames", 0)), reverse=True)

    master_csv = write_csv(master_rows, outdir, "pcap_bssid_master.csv")
    master_xlsx = write_xlsx(master_rows, outdir, "pcap_bssid_master.xlsx")

    per_rows: List[dict] = []
    for pcap_name in sorted(set(list(ap_per_pcap_counts) + list(sta_per_pcap_counts))):
        ap_c = ap_per_pcap_counts.get(pcap_name, Counter())
        sta_c = sta_per_pcap_counts.get(pcap_name, Counter())
        ap_uniq = len(ap_c)
        ap_matched = len(set(ap_c) & all_log_macs)
        eapol_f = int(eapol_per_pcap.get(pcap_name, 0))
        per_rows.append({
            "PCAP": pcap_name,
            "AP_Frames": sum(ap_c.values()),
            "AP_UniqueBSSIDs": ap_uniq,
            "AP_MatchedInLogs": ap_matched,
            "AP_MatchPct": f"{round((ap_matched/ap_uniq)*100,1) if ap_uniq else 0}%",
            "Station_Frames": sum(sta_c.values()),
            "Station_UniqueMACs": len(sta_c),
            "HandshakePresent": "Yes" if eapol_f > 0 else "No",
            "EAPOL_Frames": eapol_f,
        })
    per_csv = write_csv(per_rows, outdir, "pcap_per_file_summary.csv")

    # Top 50 tables
    ap_top = master_rows[:50]
    ap_tbl = []
    for r in ap_top:
        b = r["BSSID"]
        best_ssid = (ssid_counts_by_bssid.get(b, Counter()).most_common(1) or [("", 0)])[0][0]
        ch = (ch_counts_by_ap.get(b, Counter()).most_common(1) or [("", 0)])[0][0] or NO_DATA
        vendor = vendor_for(b, oui_db)
        ap_tbl.append((b, ssid_display(best_ssid), r["Frames"], r["MatchedInLogs"],
                        r["HandshakeSeen"], r["HandshakeConfidence"], r["EAPOLFrames"],
                        ch, best_rssi_by_ap.get(b, NO_DATA), vendor,
                        category_guess("AP", vendor, is_locally_administered(b))))

    sta_totals: Counter = Counter()
    for c in sta_per_pcap_counts.values():
        sta_totals.update(c)
    sta_tbl = []
    for sta, frames in sta_totals.most_common(50):
        ch = (ch_counts_by_sta.get(sta, Counter()).most_common(1) or [("", 0)])[0][0] or NO_DATA
        vendor = vendor_for(sta, oui_db)
        loc = "Yes" if is_locally_administered(sta) else "No"
        sta_tbl.append((sta, frames, ch, best_rssi_by_sta.get(sta, NO_DATA), vendor, loc,
                        category_guess("STA", vendor, is_locally_administered(sta))))

    per_tbl = [(r["PCAP"], r["AP_Frames"], r["AP_UniqueBSSIDs"], r["AP_MatchedInLogs"],
                r["AP_MatchPct"], r["Station_Frames"], r["Station_UniqueMACs"],
                r.get("HandshakePresent","No"), r.get("EAPOL_Frames",0)) for r in per_rows]

    html_path = os.path.join(outdir, "pcap_summary.html")
    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"/><title>PCAP Evidence Report</title>
<style>
  body{{background:black;color:limegreen;font-family:Consolas,monospace;padding:20px}}
  h1,h2{{color:#00ffcc;text-shadow:0 0 6px #00ffcc}}
  table{{border-collapse:collapse;width:100%;margin:12px 0}}
  th,td{{border:1px solid limegreen;padding:6px;vertical-align:top}}
  a{{color:cyan;text-decoration:none}} a:hover{{text-decoration:underline}}
  .notes{{color:#A0FFA0;font-style:italic}}
</style></head><body>
<div style="padding:10px;border:1px solid limegreen;margin-bottom:12px">
  <b>Navigate:</b>
  <a href="summary.html">Summary</a> |
  <a href="map.html">Map</a> |
  <a href="pcap_summary.html">PCAP Evidence</a>
</div>
<h1>PCAP Evidence Report</h1>
<p><b>Parser:</b> {escape(status)} | Generated: {escape(now_str())}</p>
<p><b>OUI DB:</b> {oui_entries} entries — {escape(oui_src)}</p>
<h2>What this means</h2>
<ul>
  <li><b>AP section</b>: beacons + probe-responses → strong evidence a network was on-air.</li>
  <li><b>Stations</b>: probe/assoc requests → nearby clients searching or joining.</li>
  <li><b>Handshake 4WAY</b> = all 4 EAPOL messages seen. PARTIAL = some. EAPOL = frames present.</li>
</ul>
<h2>Per-PCAP Summary</h2>
{_html_table(["PCAP","AP_Frames","AP_BSSIDs","AP_LogMatch","AP_MatchPct","STA_Frames","STA_MACs","Handshake","EAPOL"],per_tbl)}
<h2>Top 50 Access Points by Frames</h2>
{_html_table(["BSSID","SSID","Frames","InLogs","Handshake","HS_Conf","EAPOL","Ch","BestRSSI","Vendor","Category"],ap_tbl)}
<h2>Top 50 Stations by Frames</h2>
{_html_table(["StationMAC","Frames","Ch","BestRSSI","Vendor","LocalAdmin?","Category"],sta_tbl)}
<p class="notes">LocalAdmin=Yes → MAC is randomized; vendor and device guesses are unreliable.</p>
<p class="notes">Parser: {escape(status)}</p>
</body></html>
"""
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    return {
        "pcap_master_csv": master_csv,
        "pcap_master_xlsx": master_xlsx or NO_DATA,
        "pcap_per_file_csv": per_csv,
        "pcap_summary_html": html_path,
    }


# ---------------------------------------------------------------------------
# Summary HTML
# ---------------------------------------------------------------------------

def _auth_bucket(auth: str) -> str:
    """Classify AuthMode string into a broad security category."""
    a = (auth or "").upper()
    if "WPA3" in a:
        return "WPA3"
    if "WPA2" in a:
        return "WPA2"
    if "WPA" in a:
        return "WPA"
    if "WEP" in a:
        return "WEP"
    if "OPEN" in a or a in ("", "[]"):
        return "Open"
    return "Unknown"


def write_summary_html(centroids: List[dict], outdir: str, pcap_status: str, stats: dict) -> str:
    """
    Overhauled summary: searchable/sortable/paginated network table,
    right-click context menu with Find Address (Nominatim), security posture
    chart, handshake spotlight, drive timeline heatstrip, vendor treemap.
    """
    import json as _json
    from collections import Counter as _Counter

    path = os.path.join(outdir, "summary.html")
    generated = now_str()
    PAGE_SIZE = 50

    # ── OUI lookup ──────────────────────────────────────────────────────────
    oui_db, _oui_src, _oui_entries = load_oui_db()

    def _vendor(mac: str) -> str:
        return oui_db.get(oui_key(mac), "Unknown")

    # ── Security posture ────────────────────────────────────────────────────
    sec_counts: Dict[str, int] = {"WPA3": 0, "WPA2": 0, "WPA": 0, "WEP": 0, "Open": 0, "Unknown": 0}
    for c in centroids:
        sec_counts[_auth_bucket(c.get("AuthMode", ""))] += 1
    sec_total = max(sum(sec_counts.values()), 1)
    sec_colors = {"WPA3": "#00ff88", "WPA2": "#00ccff", "WPA": "#ffcc00",
                  "WEP": "#ff6600", "Open": "#ff2244", "Unknown": "#666"}
    sec_bars = "".join(
        f'<div class="seg" style="width:{sec_counts[k]/sec_total*100:.1f}%;background:{col}" '
        f'title="{k}: {sec_counts[k]} ({sec_counts[k]/sec_total*100:.1f}%)">'
        f'<span class="seglabel">{k} {sec_counts[k]/sec_total*100:.1f}%</span></div>'
        for k, col in sec_colors.items() if sec_counts[k]
    )
    sec_legend = " ".join(
        f'<span style="color:{col}">&#9632; {k} ({sec_counts[k]})</span>'
        for k, col in sec_colors.items() if sec_counts[k]
    )

    # ── Handshake spotlight ─────────────────────────────────────────────────
    hs_conf_color = {"FULL": "#00ff88", "PARTIAL": "#ffcc00", "PMKID": "#00ccff"}
    handshake_rows = sorted(
        [c for c in centroids if (c.get("HandshakeSeen") or "").strip().lower() == "yes"],
        key=lambda c: {"FULL": 0, "PARTIAL": 1, "PMKID": 2}.get(
            str(c.get("HandshakeConfidence", "")).upper(), 3)
    )

    def _hs_row(c: dict) -> str:
        conf = str(c.get("HandshakeConfidence", "EAPOL")).upper()
        col = hs_conf_color.get(conf, "#ff9944")
        mac = escape(c.get("MAC", ""))
        ssid = escape(c.get("TopSSID", "No Data"))
        eapol = escape(str(c.get("EAPOLFrames", 0)))
        files = escape(str(c.get("HandshakePCAPFiles", "No Data")))
        lat = c.get("CentroidLat", "")
        lon = c.get("CentroidLon", "")
        coord = f'data-lat="{lat}" data-lon="{lon}"' if lat not in (NO_DATA, "", None) else ""
        v = escape(_vendor(c.get("MAC", "")))
        return (
            f'<tr class="hs-row" data-mac="{mac}" data-ssid="{ssid}" data-vendor="{v}" {coord}>'
            f'<td><b style="color:{col}">{conf}</b></td>'
            f'<td>{mac}</td><td>{ssid}</td><td>{eapol}</td>'
            f'<td style="font-size:0.8em;max-width:200px;overflow:hidden;text-overflow:ellipsis">{files}</td>'
            f'</tr>'
        )

    hs_table_rows = "".join(_hs_row(c) for c in handshake_rows[:200])

    # ── Drive timeline heatstrip ────────────────────────────────────────────
    hour_buckets: _Counter = _Counter()
    for c in centroids:
        fs = str(c.get("FirstSeen") or "")
        if len(fs) >= 13 and ("T" in fs or " " in fs):
            sep = "T" if "T" in fs else " "
            hour_buckets[fs[:13].replace(sep, " ")] += 1

    timeline_html = ""
    if hour_buckets:
        max_b = max(hour_buckets.values()) or 1
        sorted_hrs = sorted(hour_buckets.keys())
        strips = []
        for h in sorted_hrs:
            inten = hour_buckets[h] / max_b
            g = int(20 + inten * 220)
            col = f"rgb(0,{g},60)"
            strips.append(
                f'<div class="hstrip" style="background:{col};opacity:{0.3+inten*0.7:.2f}" '
                f'title="{escape(h)}: {hour_buckets[h]} networks"></div>'
            )
        timeline_html = (
            '<div id="timeline-wrap">'
            f'<div id="timeline">{"".join(strips)}</div>'
            f'<div class="tl-label">{len(sorted_hrs)} hour buckets &nbsp;'
            f'{escape(sorted_hrs[0])} &rarr; {escape(sorted_hrs[-1])}</div>'
            "</div>"
        )

    # ── Vendor treemap ──────────────────────────────────────────────────────
    vendor_counts: _Counter = _Counter()
    for c in centroids:
        vendor_counts[_vendor(c.get("MAC", ""))] += 1
    top_vendors = vendor_counts.most_common(25)
    vendor_total = max(sum(v for _, v in top_vendors), 1)
    treemap_cells = "".join(
        f'<div class="tm-cell" style="flex:{cnt/vendor_total*100:.2f};'
        f'background:hsl({int((i*137.5)%360)},55%,16%);'
        f'border:1px solid hsl({int((i*137.5)%360)},75%,32%)" '
        f'data-vendor="{escape(vname)}" '
        f'title="{escape(vname)}: {cnt} ({cnt/vendor_total*100:.1f}%)">'
        f'<span class="tm-name">{escape(vname)}</span>'
        f'<span class="tm-count">{cnt}</span></div>'
        for i, (vname, cnt) in enumerate(top_vendors)
    )

    # ── Network table JSON (cap 8000 for page performance) ──────────────────
    table_data = []
    for c in centroids[:8000]:
        lat = c.get("CentroidLat", "")
        lon = c.get("CentroidLon", "")
        table_data.append({
            "mac": c.get("MAC", ""),
            "ssid": c.get("TopSSID", NO_DATA),
            "auth": c.get("AuthMode", NO_DATA),
            "ch": str(c.get("Channel", NO_DATA)),
            "rssi": str(c.get("BestRSSI", NO_DATA)),
            "sightings": str(c.get("Sightings", 0)),
            "risk": str(c.get("RiskScore", 0)),
            "quality": c.get("LocationQuality", NO_DATA),
            "conf": str(c.get("ConfidenceRadiusM", NO_DATA)),
            "hs": c.get("HandshakeSeen", "No"),
            "vendor": _vendor(c.get("MAC", "")),
            "lat": str(lat) if lat not in (NO_DATA, "", None) else "",
            "lon": str(lon) if lon not in (NO_DATA, "", None) else "",
            "first": str(c.get("FirstSeen", NO_DATA)),
            "last": str(c.get("LastSeen", NO_DATA)),
        })
    table_json = _json.dumps(table_data, ensure_ascii=False)

    # ── Stats block ─────────────────────────────────────────────────────────
    stat_pairs = [
        ("Unique Networks (PCAP)", stats.get("pcap_unique", 0)),
        ("Unique MACs (Logs)", stats.get("log_unique", 0)),
        ("PCAP Parser Status", pcap_status),
        ("Networks with GPS Centroids", stats.get("centroid_with_loc", 0)),
        ("Total Raw Sightings", stats.get("raw_sightings", 0)),
        ("APs Seen More Than Once", stats.get("repeat_aps", 0)),
        ("APs Across Multiple Files", stats.get("multi_file_aps", 0)),
        ("APs Across Multiple Days", stats.get("multi_day_aps", 0)),
        ("High-Quality Locations", stats.get("high_quality_locations", 0)),
        ("Medium-Quality Locations", stats.get("medium_quality_locations", 0)),
        ("Networks with Handshakes", len(handshake_rows)),
        ("PCAP ↔ Log Overlap", stats.get("overlap_text", "—")),
        ("Avg Sightings / MAC", stats.get("avg_sightings", 0)),
        ("RSSI Range (dBm)", stats.get("rssi_range", "—")),
        ("GPS Bounds", stats.get("bounds_str", "—")),
    ]
    overall_rows_html = "".join(
        f"<tr><td>{escape(str(k))}</td><td>{escape(str(v))}</td></tr>"
        for k, v in stat_pairs
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>Wardrive Analysis — {escape(generated[:10])}</title>
<style>
:root{{--bg:#050607;--fg:#00ff88;--fg2:#00ccff;--warn:#ffcc00;--danger:#ff2244;
  --border:#1a3a1a;--card:rgba(0,18,8,0.75);--font:Consolas,monospace}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--fg);font-family:var(--font);font-size:13px;padding:12px}}
h1{{color:var(--fg);text-shadow:0 0 8px var(--fg);font-size:1.35em;margin-bottom:4px}}
h2{{color:var(--fg2);font-size:1em;margin:16px 0 6px;border-bottom:1px solid var(--border);padding-bottom:3px}}
a{{color:var(--fg2);text-decoration:none}} a:hover{{text-decoration:underline}}
.card{{background:var(--card);border:1px solid var(--border);border-radius:4px;padding:12px;margin-bottom:12px}}
#navbar{{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;padding:7px 10px;
  background:rgba(0,30,15,0.6);border:1px solid var(--border);border-radius:4px}}
#navbar a{{color:var(--fg2);padding:3px 10px;border:1px solid var(--fg2);border-radius:3px;font-size:0.88em}}
#navbar a:hover{{background:rgba(0,200,255,0.1)}}
.stats-tbl{{border-collapse:collapse;width:100%}}
.stats-tbl td{{padding:4px 10px;border-bottom:1px solid var(--border)}}
.stats-tbl tr:nth-child(even){{background:rgba(0,255,136,0.04)}}
#sec-bar{{display:flex;height:26px;border-radius:3px;overflow:hidden;margin:8px 0}}
.seg{{display:flex;align-items:center;overflow:hidden;cursor:default}}
.seglabel{{color:#000;font-size:0.7em;padding:0 4px;font-weight:bold;white-space:nowrap;overflow:hidden}}
#sec-legend{{margin-top:5px;font-size:0.83em;display:flex;flex-wrap:wrap;gap:10px}}
.hs-tbl{{border-collapse:collapse;width:100%;font-size:0.86em}}
.hs-tbl th{{background:rgba(0,255,136,0.07);padding:5px 8px;text-align:left;border-bottom:1px solid var(--border)}}
.hs-tbl td{{padding:4px 8px;border-bottom:1px solid #0a1a0a}}
.hs-row:hover{{background:rgba(0,255,136,0.06);cursor:pointer}}
#timeline-wrap{{margin:6px 0}}
#timeline{{display:flex;height:34px;border-radius:3px;overflow:hidden;gap:1px;background:#060a06}}
.hstrip{{flex:1;min-width:2px}}
.tl-label{{font-size:0.74em;color:#557;margin-top:3px}}
#treemap{{display:flex;flex-wrap:wrap;height:76px;gap:2px;margin:6px 0;overflow:hidden}}
.tm-cell{{display:flex;flex-direction:column;justify-content:center;align-items:center;
  overflow:hidden;cursor:pointer;border-radius:2px;transition:opacity 0.15s;min-width:2px}}
.tm-cell:hover{{opacity:0.75}}
.tm-name{{font-size:0.63em;text-align:center;padding:0 2px;overflow:hidden;
  white-space:nowrap;text-overflow:ellipsis;max-width:100%}}
.tm-count{{font-size:0.58em;color:#888}}
#search-bar{{display:flex;gap:7px;margin-bottom:7px;flex-wrap:wrap;align-items:center}}
#search-input{{flex:1;min-width:190px;background:#060f06;border:1px solid var(--fg);
  color:var(--fg);padding:5px 10px;font-family:var(--font);font-size:13px;
  border-radius:3px;outline:none}}
#search-input::placeholder{{color:#2a4a2a}}
.fbtn{{background:#060f06;border:1px solid #2a4a2a;color:#557755;
  padding:3px 9px;font-family:var(--font);font-size:12px;border-radius:3px;cursor:pointer}}
.fbtn.active{{border-color:var(--fg);color:var(--fg);background:rgba(0,255,136,0.07)}}
#net-tbl{{border-collapse:collapse;width:100%;font-size:0.83em}}
#net-tbl th{{background:rgba(0,255,136,0.07);padding:4px 8px;text-align:left;
  border-bottom:1px solid var(--border);cursor:pointer;user-select:none;white-space:nowrap}}
#net-tbl th:hover{{color:var(--fg2)}}
#net-tbl th.sorted{{color:var(--fg2)}}
#net-tbl td{{padding:3px 8px;border-bottom:1px solid #0a140a;
  white-space:nowrap;overflow:hidden;max-width:180px;text-overflow:ellipsis}}
.net-row:hover{{background:rgba(0,255,136,0.05);cursor:pointer}}
.rhi{{color:#ff2244}}.rme{{color:#ffcc00}}.rlo{{color:#00ff88}}
.hs-y{{color:#00ff88}}.hs-n{{color:#334}}
.a-open{{color:#ff2244}}.a-wep{{color:#ff6600}}.a-wpa{{color:#ffcc00}}
.a-wpa2{{color:#00ccff}}.a-wpa3{{color:#00ff88}}
#pagination{{display:flex;gap:5px;margin-top:7px;flex-wrap:wrap;align-items:center}}
.pgb{{background:#060f06;border:1px solid #2a4a2a;color:#557755;
  padding:2px 8px;font-family:var(--font);font-size:12px;border-radius:3px;cursor:pointer}}
.pgb:hover,.pgb.active{{border-color:var(--fg);color:var(--fg)}}
#ctx-menu{{position:fixed;background:#0a1a10;border:1px solid var(--fg);
  border-radius:4px;padding:4px 0;z-index:9999;display:none;min-width:190px;
  box-shadow:0 4px 18px rgba(0,0,0,0.8)}}
.ci{{padding:6px 14px;cursor:pointer;font-size:0.88em;color:var(--fg)}}
.ci:hover{{background:rgba(0,255,136,0.12)}}
.csep{{border-top:1px solid var(--border);margin:3px 0}}
#addr-out{{margin-top:7px;color:var(--fg2);font-size:0.84em;min-height:16px;word-break:break-all}}
</style>
</head>
<body>
<h1>&#x2588; WARDRIVE ANALYSIS SUMMARY</h1>
<p style="color:#557;margin-bottom:10px">Generated: {escape(generated)} &nbsp;|&nbsp; {escape(outdir)}</p>

<div id="navbar">
  <a href="summary.html">&#x2630; Summary</a>
  <a href="map.html">&#x1F5FA; Map</a>
  <a href="wardrive_map.kml">&#x1F4CD; KML</a>
  <a href="pcap_summary.html">&#x1F4E1; PCAP</a>
  <a href="wardrive_master.csv">&#x1F4C4; CSV</a>
</div>

<div class="card">
  <h2>&#x25A0; Session Statistics</h2>
  <table class="stats-tbl"><tr><th>Metric</th><th>Value</th></tr>{overall_rows_html}</table>
</div>

<div class="card">
  <h2>&#x25A0; Security Posture</h2>
  <div id="sec-bar">{sec_bars}</div>
  <div id="sec-legend">{sec_legend}</div>
</div>

<div class="card">
  <h2>&#x25A0; Drive Coverage Timeline</h2>
  {timeline_html if timeline_html else '<p style="color:#557">No timestamped sightings available.</p>'}
</div>

<div class="card">
  <h2>&#x25A0; Manufacturer Landscape (top {len(top_vendors)})</h2>
  <div id="treemap">{treemap_cells}</div>
  <div id="vendor-lbl" style="font-size:0.78em;color:#557;margin-top:4px">Click a vendor to filter the table below.</div>
</div>

<div class="card">
  <h2>&#x25A0; Handshake Spotlight ({len(handshake_rows)} networks)</h2>
  {'<p style="color:#557">No handshakes captured in this run.</p>' if not handshake_rows else
   f'<table class="hs-tbl"><tr><th>Confidence</th><th>BSSID</th><th>SSID</th>'
   f'<th>EAPOL Frames</th><th>Source PCAPs</th></tr>'
   f'{hs_table_rows}</table>'
   f'<p style="font-size:0.77em;color:#557;margin-top:5px">Right-click a row to copy BSSID or look up address.</p>'}
</div>

<div class="card">
  <h2>&#x25A0; Network Intelligence ({min(len(centroids),8000):,} of {len(centroids):,} networks)</h2>
  <div id="search-bar">
    <input id="search-input" type="text" placeholder="Search SSID, MAC, vendor, auth mode…" autocomplete="off"/>
    <button class="fbtn active" data-f="all">All</button>
    <button class="fbtn" data-f="open">Open WiFi</button>
    <button class="fbtn" data-f="hs">Handshake</button>
    <button class="fbtn" data-f="risk">High Risk</button>
    <span id="rc" style="color:#557;font-size:0.84em"></span>
  </div>
  <div style="overflow-x:auto">
  <table id="net-tbl">
    <thead><tr>
      <th data-c="ssid">SSID &#x25BC;</th>
      <th data-c="mac">MAC &#x25BC;</th>
      <th data-c="vendor">Vendor &#x25BC;</th>
      <th data-c="auth">Security &#x25BC;</th>
      <th data-c="ch">Ch &#x25BC;</th>
      <th data-c="rssi">RSSI &#x25BC;</th>
      <th data-c="sightings">Seen &#x25BC;</th>
      <th data-c="risk">Risk &#x25BC;</th>
      <th data-c="hs">HS &#x25BC;</th>
      <th data-c="quality">Loc &#x25BC;</th>
    </tr></thead>
    <tbody id="net-tbody"></tbody>
  </table>
  </div>
  <div id="pagination"></div>
  <div id="addr-out"></div>
</div>

<div class="card">
  <h2>&#x25A0; PCAP Reports</h2>
  <ul style="line-height:2">
    <li><a href="pcap_summary.html">pcap_summary.html</a> — full PCAP analysis &amp; <a href="pcap_summary.html#handshakes">Handshake Spotlight</a></li>
    <li><a href="pcap_bssid_master.csv">pcap_bssid_master.csv</a> — BSSID master list</li>
    <li><a href="pcap_per_file_summary.csv">pcap_per_file_summary.csv</a> — per-file frame counts</li>
    <li><a href="wardrive_master.csv">wardrive_master.csv</a> — full centroid export</li>
  </ul>
  <p style="color:#557;font-size:0.8em;margin-top:7px">If PCAP shows 0: run <code>tshark -v</code> in the same shell you launch the app from.</p>
</div>

<div id="ctx-menu">
  <div class="ci" id="cc-mac">&#x1F4CB; Copy MAC</div>
  <div class="ci" id="cc-ssid">&#x1F4CB; Copy SSID</div>
  <div class="csep"></div>
  <div class="ci" id="cc-addr">&#x1F4CD; Find Address (Nominatim)</div>
  <div class="ci" id="cc-osm">&#x1F5FA; Open in OpenStreetMap</div>
  <div class="csep"></div>
  <div class="ci" id="cc-vendor">&#x1F50D; Filter by this vendor</div>
  <div class="ci" id="cc-coords">&#x1F4CB; Copy coordinates</div>
</div>

<script>
(function(){{
var DATA={table_json};
var filtered=DATA.slice(),sortCol="risk",sortDir=-1,curPage=1,PAGE={PAGE_SIZE};
var activeFilter="all",activeVendor=null;

function authCls(a){{
  a=(a||"").toUpperCase();
  if(a.indexOf("WPA3")>=0)return"a-wpa3";
  if(a.indexOf("WPA2")>=0)return"a-wpa2";
  if(a.indexOf("WPA")>=0)return"a-wpa";
  if(a.indexOf("WEP")>=0)return"a-wep";
  if(a.indexOf("OPEN")>=0)return"a-open";
  return"";
}}
function rCls(r){{var n=parseInt(r)||0;return n>=7?"rhi":n>=4?"rme":"rlo";}}
function esc(s){{return(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");}}

function applyFilters(){{
  var q=(document.getElementById("search-input").value||"").toLowerCase();
  filtered=DATA.filter(function(r){{
    if(activeVendor&&r.vendor!==activeVendor)return false;
    if(activeFilter==="open"&&r.auth.toUpperCase().indexOf("OPEN")<0)return false;
    if(activeFilter==="hs"&&r.hs!=="Yes")return false;
    if(activeFilter==="risk"&&(parseInt(r.risk)||0)<=5)return false;
    if(!q)return true;
    return(r.ssid+r.mac+r.vendor+r.auth).toLowerCase().indexOf(q)>=0;
  }});
  sortRows();
}}
function sortRows(){{
  filtered.sort(function(a,b){{
    var av=a[sortCol]||"",bv=b[sortCol]||"";
    var an=parseFloat(av),bn=parseFloat(bv);
    if(!isNaN(an)&&!isNaN(bn))return(an-bn)*sortDir;
    return av.localeCompare(bv)*sortDir;
  }});
  curPage=1;renderTable();
}}
function renderTable(){{
  var tbody=document.getElementById("net-tbody");
  var sl=filtered.slice((curPage-1)*PAGE,curPage*PAGE),html="";
  sl.forEach(function(r){{
    var ac=authCls(r.auth),rc=rCls(r.risk),hc=r.hs==="Yes"?"hs-y":"hs-n";
    html+='<tr class="net-row" data-mac="'+esc(r.mac)+'" data-ssid="'+esc(r.ssid)+
      '" data-lat="'+esc(r.lat)+'" data-lon="'+esc(r.lon)+'" data-vendor="'+esc(r.vendor)+'">';
    html+='<td title="'+esc(r.ssid)+'">'+esc(r.ssid)+'</td>';
    html+='<td>'+esc(r.mac)+'</td>';
    html+='<td title="'+esc(r.vendor)+'">'+esc(r.vendor.substring(0,22))+'</td>';
    html+='<td class="'+ac+'">'+esc(r.auth)+'</td>';
    html+='<td>'+esc(r.ch)+'</td><td>'+esc(r.rssi)+'</td>';
    html+='<td>'+esc(r.sightings)+'</td>';
    html+='<td class="'+rc+'">'+esc(r.risk)+'</td>';
    html+='<td class="'+hc+'">'+esc(r.hs)+'</td>';
    html+='<td>'+esc(r.quality)+'</td></tr>';
  }});
  tbody.innerHTML=html;
  document.getElementById("rc").textContent=
    filtered.length.toLocaleString()+" networks"+(activeVendor?" ["+activeVendor+"]":"");
  renderPages();
}}
function renderPages(){{
  var pages=Math.ceil(filtered.length/PAGE);
  var el=document.getElementById("pagination"),html='<span style="color:#557;font-size:0.84em">Page '+curPage+'/'+pages+'</span> ';
  if(curPage>1)html+='<button class="pgb" id="pp">&#x25C4;</button>';
  var lo=Math.max(1,curPage-3),hi=Math.min(pages,curPage+3);
  for(var p=lo;p<=hi;p++)html+='<button class="pgb'+(p===curPage?" active":"")+'" data-p="'+p+'">'+p+'</button>';
  if(curPage<pages)html+='<button class="pgb" id="pn">&#x25BA;</button>';
  el.innerHTML=html;
  el.querySelectorAll("[data-p]").forEach(function(b){{
    b.addEventListener("click",function(){{curPage=parseInt(b.dataset.p);renderTable();}});
  }});
  var pp=el.querySelector("#pp"),pn=el.querySelector("#pn");
  if(pp)pp.addEventListener("click",function(){{curPage--;renderTable();}});
  if(pn)pn.addEventListener("click",function(){{curPage++;renderTable();}});
}}

document.querySelectorAll("#net-tbl th[data-c]").forEach(function(th){{
  th.addEventListener("click",function(){{
    if(sortCol===th.dataset.c)sortDir*=-1;else{{sortCol=th.dataset.c;sortDir=-1;}}
    document.querySelectorAll("#net-tbl th").forEach(function(t){{t.classList.remove("sorted");}});
    th.classList.add("sorted");
    sortRows();
  }});
}});

document.getElementById("search-input").addEventListener("input",applyFilters);

document.querySelectorAll(".fbtn").forEach(function(b){{
  b.addEventListener("click",function(){{
    document.querySelectorAll(".fbtn").forEach(function(x){{x.classList.remove("active");}});
    b.classList.add("active");activeFilter=b.dataset.f;applyFilters();
  }});
}});

document.querySelectorAll(".tm-cell").forEach(function(cell){{
  cell.addEventListener("click",function(){{
    var v=cell.dataset.vendor;
    if(activeVendor===v){{
      activeVendor=null;
      document.getElementById("vendor-lbl").textContent="Click a vendor to filter the table below.";
      document.querySelectorAll(".tm-cell").forEach(function(c){{c.style.outline="none";}});
    }}else{{
      activeVendor=v;
      document.getElementById("vendor-lbl").textContent="Filtering: "+v;
      document.querySelectorAll(".tm-cell").forEach(function(c){{
        c.style.outline=c.dataset.vendor===v?"2px solid #00ff88":"none";
      }});
    }}
    applyFilters();
  }});
}});

// ── Context menu ──────────────────────────────────────────────────────────
var ctx=document.getElementById("ctx-menu"),ctxRow=null;
function showCtx(e,row){{
  ctxRow=row;
  ctx.style.left=Math.min(e.clientX,window.innerWidth-200)+"px";
  ctx.style.top=Math.min(e.clientY,window.innerHeight-220)+"px";
  ctx.style.display="block";e.preventDefault();
}}
function hideCtx(){{ctx.style.display="none";}}
document.addEventListener("contextmenu",function(e){{
  var row=e.target.closest(".net-row,.hs-row");
  if(row)showCtx(e,row);else hideCtx();
}});
document.addEventListener("click",hideCtx);
document.addEventListener("keydown",function(e){{if(e.key==="Escape")hideCtx();}});

function cp(txt){{
  if(navigator.clipboard)navigator.clipboard.writeText(txt).catch(function(){{
    var ta=document.createElement("textarea");ta.value=txt;
    document.body.appendChild(ta);ta.select();document.execCommand("copy");ta.remove();
  }});else{{
    var ta=document.createElement("textarea");ta.value=txt;
    document.body.appendChild(ta);ta.select();document.execCommand("copy");ta.remove();
  }}
}}

document.getElementById("cc-mac").addEventListener("click",function(){{if(ctxRow)cp(ctxRow.dataset.mac||"");hideCtx();}});
document.getElementById("cc-ssid").addEventListener("click",function(){{if(ctxRow)cp(ctxRow.dataset.ssid||"");hideCtx();}});
document.getElementById("cc-coords").addEventListener("click",function(){{
  if(!ctxRow)return;
  var lat=ctxRow.dataset.lat,lon=ctxRow.dataset.lon;
  cp(lat&&lon?lat+","+lon:"No coordinates");hideCtx();
}});
document.getElementById("cc-osm").addEventListener("click",function(){{
  if(!ctxRow)return;
  var lat=ctxRow.dataset.lat,lon=ctxRow.dataset.lon;
  if(lat&&lon)window.open("https://www.openstreetmap.org/?mlat="+lat+"&mlon="+lon+"&zoom=17","_blank");
  hideCtx();
}});
document.getElementById("cc-vendor").addEventListener("click",function(){{
  if(!ctxRow)return;
  var v=ctxRow.dataset.vendor||"";
  if(v){{activeVendor=v;document.getElementById("vendor-lbl").textContent="Filtering: "+v;applyFilters();}}
  hideCtx();
}});
document.getElementById("cc-addr").addEventListener("click",function(){{
  if(!ctxRow)return;
  var lat=ctxRow.dataset.lat,lon=ctxRow.dataset.lon,el=document.getElementById("addr-out");
  if(!lat||!lon){{el.textContent="No coordinates for this network.";hideCtx();return;}}
  el.textContent="Looking up address…";hideCtx();
  fetch("https://nominatim.openstreetmap.org/reverse?lat="+lat+"&lon="+lon+"&format=json",{{
    headers:{{"Accept-Language":"en","User-Agent":"WardriverAnalyzer/1.0"}}
  }}).then(function(r){{return r.json();}})
    .then(function(d){{el.textContent="Address: "+(d.display_name||"Not found");}})
    .catch(function(){{el.textContent="Address lookup failed (offline?)";}});
}});

document.querySelectorAll(".hs-row").forEach(function(row){{
  row.addEventListener("contextmenu",function(e){{showCtx(e,row);}});
}});

applyFilters();
}})();
</script>
</body>
</html>
"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path
