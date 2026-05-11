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
    s = ssid_raw if ssid_raw not in (None, "", NO_DATA) else ""
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


# ---------------------------------------------------------------------------
# CSV / XLSX
# ---------------------------------------------------------------------------

def write_csv(rows: List[dict], outdir: str, filename: str) -> str:
    path = os.path.join(outdir, filename)
    headers = list(rows[0].keys()) if rows else ["MAC"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, headers)
        w.writeheader()
        if rows:
            w.writerows(rows)
    return path


def write_xlsx(rows: List[dict], outdir: str, filename: str) -> Optional[str]:
    try:
        from openpyxl import Workbook  # type: ignore
    except Exception:
        return None
    path = os.path.join(outdir, filename)
    wb = Workbook()
    ws = wb.active
    ws.title = "Data"
    headers = list(rows[0].keys()) if rows else ["MAC"]
    ws.append(headers)
    for r in rows:
        ws.append([r.get(h, NO_DATA) for h in headers])
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
            f"Confidence (m): {escape(str(c.get('ConfidenceRadiusM', NO_DATA)))}<br>"
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
            f"Confidence (m): {escape(str(c.get('ConfidenceRadiusM', NO_DATA)))}<br>"
            f"Stability: {escape(str(c.get('Stability', NO_DATA)))}<br>"
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
                f"L.circle([{lat},{lon}], {{radius:{conf_m}, weight:1, fillOpacity:0.12}}).addTo(layerConfidence);"
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

    var layerCentroids  = L.layerGroup().addTo(map);
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

def write_summary_html(centroids: List[dict], outdir: str, pcap_status: str, stats: dict) -> str:
    path = os.path.join(outdir, "summary.html")
    overall = [
        ("Unique Networks (PCAP)", stats["pcap_unique"]),
        ("Unique MACs (Logs)", stats["log_unique"]),
        ("PCAP Parser", pcap_status),
        ("Networks with GPS Centroids", stats["centroid_with_loc"]),
        ("Total Raw Sightings", stats["raw_sightings"]),
        ("PCAP ↔ Log Overlap", stats["overlap_text"]),
        ("Avg Sightings / MAC", stats["avg_sightings"]),
        ("RSSI Range (dBm)", stats["rssi_range"]),
        ("GPS Bounds", stats["bounds_str"]),
    ]
    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"/><title>Wardrive Analysis Summary</title>
<style>
  body{{background:black;color:limegreen;font-family:Consolas,monospace;padding:20px}}
  h1,h2{{color:#00FF00;text-shadow:0 0 5px #00FF00}}
  table{{border-collapse:collapse;width:100%;margin-bottom:20px}}
  th,td{{border:1px solid limegreen;padding:8px;text-align:left}}
  a{{color:cyan;text-decoration:none}} a:hover{{text-decoration:underline}}
  .notes{{font-style:italic;color:#A0FFA0}}
</style></head><body>
<h1>WARDRIVE ANALYSIS SUMMARY</h1>
<p>Generated: {escape(now_str())}</p>
<div style="padding:10px;border:1px solid limegreen;margin-bottom:12px">
  <b>Navigate:</b>
  <a href="summary.html">Summary</a> |
  <a href="map.html">Map</a> |
  <a href="wardrive_map.kml">KML</a> |
  <a href="pcap_summary.html">PCAP Evidence</a>
</div>
<h2>Overall Statistics</h2>
{_html_table(["Metric","Value"], overall)}
<h2>How to read this</h2>
<ul>
  <li><b>PCAP data</b> = radio evidence that a Wi-Fi network was on-air.</li>
  <li><b>Log data</b> = GPS evidence of where you were when you saw it.</li>
  <li><b>Overlap</b> = same BSSID in both sources — highest confidence.</li>
  <li><b>Centroid</b> = weighted best-guess location of the AP.</li>
  <li><b>Confidence circle</b> = uncertainty radius. Bigger = less certain.</li>
  <li>The <b>Map</b> includes a signal heatmap and your drive route — toggle layers top-right.</li>
</ul>
<h2>Reports</h2>
<ul>
  <li><a href="pcap_summary.html">PCAP Evidence Report</a> — AP + station inventory, handshake detection.</li>
  <li><a href="pcap_bssid_master.csv">pcap_bssid_master.csv</a> — AP BSSIDs from PCAPs.</li>
  <li><a href="wardrive_master.csv">wardrive_master.csv</a> — Full centroid master table.</li>
</ul>
<p class="notes">Boot sequence complete. AWAITING NEXT SCAN...</p>
</body></html>
"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path
