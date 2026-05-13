"""
core.py — Wardrive Analyzer Core (Step 3B)

Educational goals:
- Outputs explain what the data is, why it matters, and how to interpret results.
- High-school level explanations in HTML summaries.
- "Evidence first": PCAP = radio evidence, Logs = GPS evidence, Overlap = confidence.

Step 3B changes:
- PCAP parsing uses tshark directly (more reliable on Windows + EXE packaging).
- Adds PCAP reports:
    * pcap_summary.html
    * pcap_bssid_master.csv/.xlsx
    * pcap_per_file_summary.csv
- Map confidence circles OFF by default (toggle layer on after load for performance).

Match key:
- MAC/BSSID only (SSID is display-only because defaults repeat).
"""

from __future__ import annotations

import csv
import json
import re
import math
import random
import os
import sys
import shutil
import subprocess
from collections import defaultdict, Counter
from dataclasses import dataclass
from datetime import datetime
from html import escape
from typing import Dict, List, Optional, Tuple, Set

# -----------------------------
# Tunables (safe defaults)
# -----------------------------
NO_DATA = "No Data"

CORE_REVISION = "3D-r02i-live-console-stream"

def resource_path(*parts: str) -> str:
    """Resolve paths for dev + PyInstaller onefile."""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, *parts)


REPORT_BG_CANDIDATES = [
    "assets/demogif1.gif",
    "assets/demo1.gif",
    "assets/demo2.gif",
    "assets/demo3.gif",
    "assets/demo4.gif",
    "assets/demo5.gif",
    "assets/demo6.gif",
]


def copy_report_background(outdir: str) -> str | None:
    """Copy a baked pixel/demoscene GIF into the run folder for HTML reports."""
    try:
        src_rel = random.choice(REPORT_BG_CANDIDATES)
        src = resource_path(src_rel)
        if not os.path.exists(src):
            return None
        dst = os.path.join(outdir, "report_bg.gif")
        shutil.copy2(src, dst)
        return dst
    except Exception:
        return None


from typing import Callable

def _emit(cb: Optional[Callable[[str], None]], msg: str) -> None:
    if cb:
        cb(msg)


def _emit_output_checklist(cb: Optional[Callable[[str], None]], run_dir: str, expected: List[str]) -> None:
    _emit(cb, '')
    _emit(cb, '=== Run Output Checklist ===')
    for rel in expected:
        p = os.path.join(run_dir, rel)
        ok = os.path.exists(p)
        mark = '✅' if ok else '❌'
        _emit(cb, f'{mark} {rel}')
    _emit(cb, '=== End Checklist ===')



# -----------------------------
# Console staging helpers
# -----------------------------
def _group_patterns(files: List[str]) -> Dict[str, List[str]]:
    """Group files into human-friendly buckets based on name patterns."""
    groups: Dict[str, List[str]] = defaultdict(list)
    for p in files:
        bn = os.path.basename(p)
        m = re.match(r"^(.*?)(?:_\d+)?\.(\w+)$", bn)
        if m:
            stem, ext = m.group(1), m.group(2).lower()
            key = f"{stem}_*.{ext}"
        else:
            key = bn
        groups[key].append(bn)
    return groups


def _emit_stage_groups(status_cb: Optional[Callable[[str], None]], title: str, files: List[str], explain_map: Dict[str, str]) -> None:
    """Emit grouped, educational stage commentary into the console/log."""
    if not files:
        return
    _emit(status_cb, f"=== STAGE: {title} ===")
    groups = _group_patterns(files)
    for key in sorted(groups.keys()):
        sample = groups[key][:3]
        sample_txt = ", ".join(sample) + ("…" if len(groups[key]) > 3 else "")
        expl = explain_map.get(key, explain_map.get(key.split("_*.")[0], ""))
        _emit(status_cb, f"[*] {key}  ({len(groups[key])} file(s))")
        if expl:
            _emit(status_cb, f"    {expl}")
        _emit(status_cb, f"    ex: {sample_txt}")
    _emit(status_cb, "")

# Balanced weighting (RSSI + GPS accuracy)
RSSI_REF = -90.0
RSSI_SCALE = 8.0
ACC_FLOOR_M = 5.0
ACC_DEFAULT_M = 25.0

# Robustness: drop weakest RSSI samples to reduce multipath/outliers
DROP_WEAKEST_FRAC = 0.10  # 10%

# KML confidence circle detail
KML_CIRCLE_POINTS = 36

# Leaflet CDN assets (later we can bundle locally for offline)
LEAFLET_CSS = "https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"
LEAFLET_JS = "https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"


# -----------------------------
# Helpers
# -----------------------------
def norm_mac(mac: str) -> str:
    return (mac or "").strip().upper()


def safe_str(x: Optional[str]) -> str:
    return x if x not in ("", None) else NO_DATA


def safe_float(x: Optional[str]) -> Optional[float]:
    try:
        if x in (None, "", NO_DATA):
            return None
        return float(x)
    except Exception:
        return None


def safe_int(x: Optional[str]) -> Optional[int]:
    try:
        if x in (None, "", NO_DATA):
            return None
        return int(float(x))
    except Exception:
        return None


def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Distance between two GPS points in meters."""
    R = 6371000.0
    p1 = math.radians(lat1)
    p2 = math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * R * math.asin(math.sqrt(a))


def json_str(s: str) -> str:
    """Minimal JS string escaping."""
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


def json_arr(items: List[str]) -> str:
    return "[" + ",".join(items) + "]"


# -----------------------------
# Data model
# -----------------------------
@dataclass
class Sighting:
    """One row/observation from a wardrive log."""
    mac: str
    ssid: str
    auth: str
    channel: str
    rssi: Optional[int]
    lat: Optional[float]
    lon: Optional[float]
    acc_m: Optional[float]
    first_seen: str
    source_file: str


# -----------------------------
# Wardrive log parsing (ESP32 Marauder WigleWifi-1.4 style)
# -----------------------------
def load_wardrive_logs(files: List[str], status_cb: Optional[Callable[[str], None]] = None) -> Tuple[Dict[str, List[Sighting]], Dict[str, Set[str]]]:
    """
    Reads wardrive logs and returns:
      - sightings_by_mac: MAC -> list of Sighting
      - logfiles_by_mac:  MAC -> set of log filenames where seen

    We assume header row includes:
      MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,...AccuracyMeters
    If a file is missing a column, we put NO_DATA.
    """
    sightings_by_mac: Dict[str, List[Sighting]] = defaultdict(list)
    logfiles_by_mac: Dict[str, Set[str]] = defaultdict(set)

    total_files = len(files)
    for idx_file, path in enumerate(files, start=1):
        _emit(status_cb, f"[*] P4R51NG L0G {idx_file}/{total_files}: {os.path.basename(path)}")
        headers = None
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("WigleWifi"):
                        continue
                    if line.startswith("MAC,"):
                        headers = [h.strip() for h in next(csv.reader([line]))]
                        continue
                    if not headers or "," not in line:
                        continue

                    values = [v.strip() for v in next(csv.reader([line]))]
                    row = dict(zip(headers, values))

                    mac = norm_mac(row.get("MAC", ""))
                    if not mac:
                        continue

                    s = Sighting(
                        mac=mac,
                        ssid=safe_str(row.get("SSID")),
                        auth=safe_str(row.get("AuthMode")),
                        channel=safe_str(row.get("Channel")),
                        rssi=safe_int(row.get("RSSI")),
                        lat=safe_float(row.get("CurrentLatitude")),
                        lon=safe_float(row.get("CurrentLongitude")),
                        acc_m=safe_float(row.get("AccuracyMeters")),
                        first_seen=safe_str(row.get("FirstSeen")),
                        source_file=os.path.basename(path),
                    )
                    sightings_by_mac[mac].append(s)
                    logfiles_by_mac[mac].add(os.path.basename(path))
        except Exception:
            # Keep the run alive even if one file is weird.
            continue

    return sightings_by_mac, logfiles_by_mac


# -----------------------------
# Centroid + confidence estimation
# -----------------------------
def rssi_weight(rssi: int) -> float:
    """
    RSSI is negative; stronger = less negative.
    We map to a smooth positive weight. Balanced: doesn't explode for very strong signals.
    """
    return math.exp((rssi - RSSI_REF) / RSSI_SCALE)


def acc_weight(acc_m: Optional[float]) -> float:
    """Smaller accuracy meters = more trustworthy; cap best-case so it doesn't dominate."""
    a = acc_m if acc_m is not None else ACC_DEFAULT_M
    a = max(a, ACC_FLOOR_M)
    return 1.0 / a


def compute_centroid_and_confidence(
    sightings: List[Sighting],
) -> Tuple[Optional[float], Optional[float], Optional[float], Optional[int]]:
    """
    Returns:
      (centroid_lat, centroid_lon, confidence_radius_m, used_points_count)

    Confidence radius is weighted RMS distance from centroid.
    More observations + smaller radius => more stable estimate.
    """
    valid = [s for s in sightings if s.lat is not None and s.lon is not None and s.rssi is not None]
    if not valid:
        return None, None, None, None

    # Drop weakest fraction (robustness against multipath/outliers)
    valid_sorted = sorted(valid, key=lambda s: s.rssi if s.rssi is not None else -999)
    drop_n = int(len(valid_sorted) * DROP_WEAKEST_FRAC)
    kept = valid_sorted[drop_n:] if drop_n < len(valid_sorted) else valid_sorted

    sum_w = 0.0
    sum_lat = 0.0
    sum_lon = 0.0
    for s in kept:
        w = rssi_weight(s.rssi) * acc_weight(s.acc_m)
        sum_w += w
        sum_lat += w * s.lat
        sum_lon += w * s.lon

    if sum_w <= 0:
        return None, None, None, None

    clat = sum_lat / sum_w
    clon = sum_lon / sum_w

    sum_wd2 = 0.0
    for s in kept:
        w = rssi_weight(s.rssi) * acc_weight(s.acc_m)
        d = haversine_m(clat, clon, s.lat, s.lon)
        sum_wd2 += w * (d**2)

    rms = math.sqrt(sum_wd2 / sum_w) if sum_w > 0 else None
    return clat, clon, rms, len(kept)


def stability_score(conf_radius_m: Optional[float], n: int) -> int:
    """
    Stability 0–100 heuristic:
      - More sightings => higher stability (saturates)
      - Smaller confidence radius => higher stability
    """
    if conf_radius_m is None or n <= 0:
        return 0
    obs_factor = 1.0 - math.exp(-n / 6.0)
    rad_factor = 1.0 / (1.0 + (conf_radius_m / 50.0))
    score = int(round(100.0 * obs_factor * rad_factor))
    return max(0, min(100, score))


# -----------------------------
# Risk scoring (simple + explainable)
# -----------------------------
def compute_risk(auth: str, ssid: str, best_rssi: Optional[int]) -> int:
    """
    Educational risk score (not a "hack score"):
      - OPEN => +3
      - WEP  => +4
      - WPA (legacy/mixed) => +1
      - Hidden/empty SSID => +1 (not inherently risky, but notable)
      - Strong RSSI (> -60) => +1 (close proximity)
    """
    score = 0
    a = (auth or "").upper()

    if "OPEN" in a:
        score += 3
    if "WEP" in a:
        score += 4
    if "WPA" in a and "WPA3" not in a:
        score += 1

    if ssid in (NO_DATA, "", None):
        score += 1

    if best_rssi is not None and best_rssi > -60:
        score += 1

    return score


# -----------------------------
# Artifact writers (CSV/XLSX/KML/HTML)
# -----------------------------
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
    """Optional Excel output. If openpyxl isn't installed, we skip xlsx but keep CSV."""
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


def kml_circle(lat: float, lon: float, radius_m: float) -> str:
    """Approximate a circle polygon for confidence radius visualization in Google Earth."""
    coords = []
    R = 6371000.0
    lat1 = math.radians(lat)
    lon1 = math.radians(lon)

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
        if c.get("CentroidLat") in (NO_DATA, "", None) or c.get("CentroidLon") in (NO_DATA, "", None):
            continue

        lat = float(c["CentroidLat"])
        lon = float(c["CentroidLon"])
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

        # Confidence circle polygon
        conf = c.get("ConfidenceRadiusM", NO_DATA)
        try:
            conf_m = float(conf)
        except Exception:
            conf_m = None

        if conf_m is not None and conf_m > 0:
            ring = kml_circle(lat, lon, conf_m)
            placemarks.append(
                "<Placemark>"
                f"<name>{name} (confidence)</name>"
                "<Style><LineStyle><color>ff00ffff</color><width>1</width></LineStyle>"
                "<PolyStyle><color>2200ffff</color></PolyStyle></Style>"
                "<Polygon><outerBoundaryIs><LinearRing>"
                f"<coordinates>{ring}</coordinates>"
                "</LinearRing></outerBoundaryIs></Polygon>"
                "</Placemark>"
            )

    kml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<kml xmlns="http://www.opengis.net/kml/2.2"><Document>'
        "<name>Wardrive Centroids</name>"
        + "".join(placemarks)
        + "</Document></kml>"
    )

    with open(path, "w", encoding="utf-8") as f:
        f.write(kml)

    return path


def write_map_html(centroids: List[dict], outdir: str, circles_enabled_default: bool = False) -> str:
    """
    Centroids-only by default. Confidence circles are available but OFF by default for performance.
    """
    path = os.path.join(outdir, "map.html")

    pts = [
        c
        for c in centroids
        if c.get("CentroidLat") not in (NO_DATA, "", None) and c.get("CentroidLon") not in (NO_DATA, "", None)
    ]

    markers_js: List[str] = []
    circles_js: List[str] = []
    bounds_js: List[str] = []

    for c in pts:
        lat = float(c["CentroidLat"])
        lon = float(c["CentroidLon"])
        bounds_js.append(f"[{lat},{lon}]")

        popup = (
            f"<b>{escape(c.get('TopSSID', NO_DATA))}</b><br>"
            f"MAC: {escape(c['MAC'])}<br>"
            f"Security: {escape(c.get('AuthMode', NO_DATA))}<br>"
            f"Obs: {escape(str(c.get('Sightings', NO_DATA)))}<br>"
            f"Confidence (m): {escape(str(c.get('ConfidenceRadiusM', NO_DATA)))}<br>"
            f"Stability: {escape(str(c.get('Stability', NO_DATA)))}<br>"
            f"Seen in PCAP: {escape(c.get('SeenInPCAP', NO_DATA))}"
        )
        markers_js.append(
            f"L.marker([{lat},{lon}]).bindPopup({json_str(popup)}).addTo(layerCentroids);"
        )

        conf = c.get("ConfidenceRadiusM", NO_DATA)
        try:
            conf_m = float(conf)
        except Exception:
            conf_m = None

        if conf_m is not None and conf_m > 0:
            circles_js.append(
                f"L.circle([{lat},{lon}], {{radius:{conf_m}, weight:1, fillOpacity:0.12}}).addTo(layerConfidence);"
            )

    conf_add_line = "layerConfidence.addTo(map);" if circles_enabled_default else ""

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8"/>
<title>Wardrive Map (Centroids)</title>
<link rel="stylesheet" href="{LEAFLET_CSS}"/>
<script src="{LEAFLET_JS}"></script>
<style>
  body {{ margin:0; background:#050607; color:#00ff88; font-family:Consolas, monospace; }}
  #map {{ height:100vh; width:100vw; }}
</style>
</head>
<body>
<div id="map"></div>
<script>
(function() {{
  try {{
    var map = L.map('map');
    var tiles = L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
      maxZoom: 19,
      attribution: '&copy; OpenStreetMap contributors'
    }}).addTo(map);

    tiles.on('tileerror', function() {{
      console.warn("Tile failed to load. You may be offline or blocked from external resources.");
    }});

    var layerCentroids = L.layerGroup().addTo(map);
    var layerConfidence = L.layerGroup();
    {conf_add_line}

    {''.join(markers_js)}
    {''.join(circles_js)}

    L.control.layers(null, {{
      "Centroids": layerCentroids,
      "Confidence (toggle)": layerConfidence
    }}, {{collapsed:false}}).addTo(map);

    var pts = {json_arr(bounds_js)};
    if (pts.length > 0) {{
      map.fitBounds(L.latLngBounds(pts).pad(0.15));
    }} else {{
      map.setView([0,0], 2);
    }}
  }} catch (e) {{
    console.error(e);
    document.body.innerHTML = "<pre style='color:#ff5577; padding:20px;'>Map render error: " + e + "</pre>";
  }}
}})();
</script>
</body>
</html>
"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

    return path



# -----------------------------
# Step 3B+: tshark-based PCAP parsing + richer PCAP reports (AP + Stations + All Roles)
# -----------------------------
def is_locally_administered(mac: str) -> bool:
    """
    Locally administered MAC addresses are often randomized (privacy feature).
    Bit 1 of the first octet set => locally administered.
    """
    try:
        first = int(mac.split(":")[0], 16)
        return (first & 0x02) != 0
    except Exception:
        return False


def oui_key(mac: str) -> str:
    parts = (mac or "").upper().split(":")
    if len(parts) >= 3:
        return ":".join(parts[:3])
    return ""


def load_oui_db() -> Tuple[Dict[str, str], str, int]:
    """
    Loads an optional OUI database if present (oui.csv next to the script or bundled).
    Returns (oui_map, source_path, entries).
    """
    import sys

    base_path = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    candidates = [
        os.path.join(base_path, "oui.csv"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "oui.csv"),
    ]
    for p in candidates:
        if os.path.exists(p):
            try:
                # Try a few common formats:
                # 1) "Assignment","Organization Name",...
                # 2) legacy IEEE text exported to csv-like lines
                with open(p, "r", encoding="utf-8", errors="ignore") as f:
                    sample = f.read(4096)
                # Reset read
                with open(p, "r", encoding="utf-8", errors="ignore") as f:
                    reader = csv.reader(f)
                    rows = list(reader)

                if not rows:
                    return {}, p, 0

                header = [h.strip().lower() for h in rows[0]]
                m: Dict[str, str] = {}

                # Format A: Assignment column
                if "assignment" in header:
                    ia = header.index("assignment")
                    # org name column varies
                    iname = header.index("organization name") if "organization name" in header else None
                    if iname is None:
                        # fallback to second column
                        iname = 1 if len(header) > 1 else 0
                    for r in rows[1:]:
                        if len(r) <= max(ia, iname):
                            continue
                        raw = r[ia].strip().upper()
                        assign = raw.replace("-", ":")

                        # Common IEEE oui.csv format is just 6 hex chars (e.g. 286FB9)
                        # Normalize to XX:XX:XX so vendor_for() can match oui_key().
                        if re.fullmatch(r"[0-9A-F]{6}", assign):
                            assign = ":".join([assign[i : i + 2] for i in range(0, 6, 2)])

                        # Some exports already include delimiters.
                        if re.fullmatch(r"[0-9A-F]{2}(:[0-9A-F]{2}){2}", assign):
                            m[assign] = r[iname].strip() or NO_DATA
                    return m, p, len(m)

                # Format B: try to find "XX-XX-XX" patterns anywhere
                for r in rows:
                    if not r:
                        continue
                    line = ",".join(r)
                    mm = re.search(r"([0-9A-F]{2}[-:]){2}[0-9A-F]{2}", line.upper())
                    if not mm:
                        continue
                    key = mm.group(0).replace("-", ":")
                    # remainder as vendor
                    vendor = line[mm.end():].strip(" ,\t")
                    vendor = vendor if vendor else NO_DATA
                    if re.fullmatch(r"[0-9A-F]{2}(:[0-9A-F]{2}){2}", key):
                        m[key] = vendor
                return m, p, len(m)
            except Exception:
                return {}, p, 0

    return {}, NO_DATA, 0


def vendor_for(mac: str, oui_db: Dict[str, str]) -> str:
    k = oui_key(mac)
    if k and k in oui_db:
        return oui_db[k]
    return NO_DATA


def freq_to_channel(freq_mhz: Optional[float]) -> Optional[int]:
    """Best-effort mapping of RF frequency (MHz) to Wi‑Fi channel."""
    if freq_mhz is None:
        return None
    f = float(freq_mhz)

    # 2.4 GHz
    if 2412 <= f <= 2472:
        return int(round((f - 2412) / 5)) + 1
    if int(round(f)) == 2484:
        return 14

    # 5 GHz (common)
    if 5000 <= f <= 5900:
        return int(round((f - 5000) / 5))

    # 6 GHz (rough; ch 1 = 5955 MHz)
    if 5925 <= f <= 7125:
        return int(round((f - 5950) / 5))

    return None


def ssid_ascii_hex(ssid_raw: str) -> Tuple[str, Optional[str]]:
    """
    Returns (ascii_display, hex_string_or_none).
    - If ssid_raw looks hex-ish, we attempt decode bytes.fromhex() to ascii.
    - Always provide HEX when we can represent bytes reliably.
    """
    s = ssid_raw if ssid_raw not in (None, "", NO_DATA) else ""
    if not s:
        return "<MISSING>", None

    # If tshark gave us a hex-looking SSID (all hex chars, even length), try decode.
    if re.fullmatch(r"[0-9A-Fa-f]+", s) and (len(s) % 2 == 0) and len(s) >= 2:
        try:
            b = bytes.fromhex(s)
            ascii_guess = b.decode("utf-8", errors="ignore").strip() or "<MISSING>"
            return ascii_guess, s.lower()
        except Exception:
            return "<MISSING>", s.lower()

    # Otherwise treat as a normal string; compute a hex representation of its utf-8 bytes.
    try:
        b = s.encode("utf-8", errors="ignore")
        hx = b.hex() if b else None
    except Exception:
        hx = None
    return s, hx


def ssid_ascii_hex_display(ssid_raw: str) -> str:
    a, hx = ssid_ascii_hex(ssid_raw)
    if hx:
        return f"ASCII: {a} | HEX: {hx}"
    return f"ASCII: {a}"


def category_guess(role: str, vendor: str, locally_admin: bool) -> str:
    """
    Light-weight, explainable device-type guess.
    - If role is observed AP, say so.
    - If locally administered (randomized), guesses are unreliable.
    """
    if role == "AP":
        # still add a vendor hint when present
        if "NETGEAR" in vendor.upper() or "TP-LINK" in vendor.upper() or "ARCADYAN" in vendor.upper():
            return "Access Point/Router (guess)"
        return "Access Point (observed role)"
    if locally_admin:
        return "Unknown"
    v = vendor.upper()
    if "APPLE" in v:
        return "Phone/Tablet (guess)"
    if "SAMSUNG" in v:
        return "Phone/Tablet (guess)"
    if "MICROSOFT" in v or "INTEL" in v or "DELL" in v or "LENOVO" in v:
        return "PC/Laptop (guess)"
    return "Wireless client (unknown type)"


def _run_tshark_ap_fields(pcap_path: str, tshark_exe: str) -> List[Tuple[str, str, Optional[float], Optional[int]]]:
    """
    Extract AP-like evidence from beacon/probe-response:
      (BSSID, SSID, channel_freq_mhz, RSSI)
    """
    cmd = [
        tshark_exe,
        "-r",
        pcap_path,
        "-Y",
        "wlan.fc.type_subtype==0x08 || wlan.fc.type_subtype==0x05",
        "-T",
        "fields",
        "-E",
        "separator=,",
        "-e",
        "wlan.bssid",
        "-e",
        "wlan.ssid",
        "-e",
        "radiotap.channel.freq",
        "-e",
        "radiotap.dbm_antsignal",
    ]

    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="ignore")
    except TypeError:
        cp = subprocess.run(cmd, capture_output=True, text=True)

    if cp.returncode != 0:
        return []

    out: List[Tuple[str, str, Optional[float], Optional[int]]] = []
    for line in cp.stdout.splitlines():
        parts = [p.strip() for p in line.split(",")]
        if not parts or not parts[0]:
            continue
        bssid = norm_mac(parts[0])
        ssid = parts[1] if len(parts) > 1 and parts[1] else NO_DATA

        freq = None
        if len(parts) > 2 and parts[2]:
            try:
                freq = float(parts[2])
            except Exception:
                freq = None

        rssi = None
        if len(parts) > 3 and parts[3]:
            try:
                rssi = int(float(parts[3]))
            except Exception:
                rssi = None

        out.append((bssid, ssid, freq, rssi))
    return out


def _run_tshark_station_fields(pcap_path: str, tshark_exe: str) -> List[Tuple[str, Optional[float], Optional[int]]]:
    """
    Extract station/client evidence from management frames that typically originate from clients:
      - Probe Request (0x04)
      - Association Request (0x00)
      - Reassociation Request (0x02)

    Returns (StationMAC, channel_freq_mhz, RSSI)
    """
    cmd = [
        tshark_exe,
        "-r",
        pcap_path,
        "-Y",
        "wlan.fc.type==0 && (wlan.fc.type_subtype==0x04 || wlan.fc.type_subtype==0x00 || wlan.fc.type_subtype==0x02)",
        "-T",
        "fields",
        "-E",
        "separator=,",
        "-e",
        "wlan.sa",
        "-e",
        "radiotap.channel.freq",
        "-e",
        "radiotap.dbm_antsignal",
    ]

    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="ignore")
    except TypeError:
        cp = subprocess.run(cmd, capture_output=True, text=True)

    if cp.returncode != 0:
        return []

    out: List[Tuple[str, Optional[float], Optional[int]]] = []
    for line in cp.stdout.splitlines():
        parts = [p.strip() for p in line.split(",")]
        if not parts or not parts[0]:
            continue
        sta = norm_mac(parts[0])

        freq = None
        if len(parts) > 1 and parts[1]:
            try:
                freq = float(parts[1])
            except Exception:
                freq = None

        rssi = None
        if len(parts) > 2 and parts[2]:
            try:
                rssi = int(float(parts[2]))
            except Exception:
                rssi = None

        out.append((sta, freq, rssi))
    return out


def _run_tshark_eapol_fields(pcap_path: str, tshark_exe: str) -> List[Tuple[str, str, str, Optional[int]]]:
    """Return EAPOL rows (bssid, sa, da, msg_no) for handshake detection.

    We treat presence of EAPOL as "handshake material". If tshark exposes a message number
    (often 1-4 for the 4-way handshake), we can estimate confidence.
    """
    cmd = [
        tshark_exe,
        "-r",
        pcap_path,
        "-Y",
        "eapol",
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-E",
        "quote=d",
        "-e",
        "wlan.bssid",
        "-e",
        "wlan.sa",
        "-e",
        "wlan.da",
        # Some tshark builds expose this as wlan_rsna_eapol.keydes.msg; if not, we'll just get blanks.
        "-e",
        "wlan_rsna_eapol.keydes.msg",
    ]
    rows: List[Tuple[str, str, str, Optional[int]]] = []
    try:
        raw = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode("utf-8", errors="ignore")
    except Exception:
        return rows

    for line in raw.splitlines():
        parts = [p.strip().strip('"') for p in line.split("\t")]
        if not parts:
            continue
        bssid = (parts[0] if len(parts) > 0 else "").strip()
        sa = (parts[1] if len(parts) > 1 else "").strip()
        da = (parts[2] if len(parts) > 2 else "").strip()
        msg_raw = (parts[3] if len(parts) > 3 else "").strip()
        msg_no: Optional[int] = None
        if msg_raw.isdigit():
            try:
                msg_no = int(msg_raw)
            except Exception:
                msg_no = None
        if bssid:
            rows.append((bssid.upper(), sa.upper() if sa else "", da.upper() if da else "", msg_no))
    return rows


def load_pcaps_tshark(
    pcap_files: List[str],
    status_cb: Optional[Callable[[str], None]] = None,
) -> Tuple[
    Set[str],                      # ap_bssids
    Dict[str, Counter],            # ap_per_pcap_counts (bssid->frames)
    Dict[str, Counter],            # sta_per_pcap_counts (sta->frames)
    Dict[str, Counter],            # ssid_counts_by_bssid
    Dict[str, Counter],            # ch_counts_by_ap
    Dict[str, int],                # best_rssi_by_ap
    Dict[str, Counter],            # ch_counts_by_sta
    Dict[str, int],                # best_rssi_by_sta
    Dict[str, Set[str]],           # pcaps_by_ap
    Dict[str, Set[str]],           # pcaps_by_sta
    Dict[str, int],                # eapol_per_pcap (pcap_name->count)
    Dict[str, int],                # eapol_by_bssid (bssid->count)
    Dict[str, str],                # handshake_conf_by_bssid (bssid->NONE/EAPOL/PARTIAL/4WAY)
    str                            # status
]:
    """
    Rich PCAP parser:
      - AP evidence from beacons/probe-responses
      - Station evidence from probe/assoc/reassoc requests
    """
    tshark_exe = shutil.which("tshark")
    if not tshark_exe:
        return (
            set(),           # ap_bssids
            {},              # ap_per_pcap_counts
            {},              # sta_per_pcap_counts
            defaultdict(Counter),  # ssid_counts_by_bssid
            defaultdict(Counter),  # ch_counts_by_ap
            {},              # best_rssi_by_ap
            defaultdict(Counter),  # ch_counts_by_sta
            {},              # best_rssi_by_sta
            defaultdict(set),      # pcaps_by_ap
            defaultdict(set),      # pcaps_by_sta
            {},              # eapol_per_pcap
            {},              # eapol_by_bssid
            {},              # handshake_conf_by_bssid
            "tshark not found in PATH; PCAP parsing skipped.",
        )

    ap_bssids: Set[str] = set()
    ap_per_pcap_counts: Dict[str, Counter] = {}
    sta_per_pcap_counts: Dict[str, Counter] = {}

    ssid_counts_by_bssid: Dict[str, Counter] = defaultdict(Counter)
    ch_counts_by_ap: Dict[str, Counter] = defaultdict(Counter)
    best_rssi_by_ap: Dict[str, int] = {}

    ch_counts_by_sta: Dict[str, Counter] = defaultdict(Counter)
    best_rssi_by_sta: Dict[str, int] = {}

    pcaps_by_ap: Dict[str, Set[str]] = defaultdict(set)
    pcaps_by_sta: Dict[str, Set[str]] = defaultdict(set)

    # Handshake / EAPOL signals
    eapol_per_pcap: Dict[str, int] = {}
    eapol_by_bssid: Dict[str, int] = defaultdict(int)
    msg_seen_by_bssid: Dict[str, Set[int]] = defaultdict(set)

    total_pcaps = len(pcap_files)
    for idx_pcap, pcap in enumerate(pcap_files, start=1):
        _emit(status_cb, f"[*] P4R51NG PCAP {idx_pcap}/{total_pcaps}: {os.path.basename(pcap)}")
        pcap_name = os.path.basename(pcap)

        # --- AP evidence ---
        ap_counts = Counter()
        ap_rows = _run_tshark_ap_fields(pcap, tshark_exe)
        for bssid, ssid, freq, rssi in ap_rows:
            ap_counts[bssid] += 1
            ap_bssids.add(bssid)
            pcaps_by_ap[bssid].add(pcap_name)

            if ssid:
                ssid_counts_by_bssid[bssid][ssid] += 1

            ch = freq_to_channel(freq)
            if ch is not None:
                ch_counts_by_ap[bssid][str(ch)] += 1

            if rssi is not None:
                if bssid not in best_rssi_by_ap or rssi > best_rssi_by_ap[bssid]:
                    best_rssi_by_ap[bssid] = rssi

        ap_per_pcap_counts[pcap_name] = ap_counts

        # --- Station evidence ---
        sta_counts = Counter()
        sta_rows = _run_tshark_station_fields(pcap, tshark_exe)
        for sta, freq, rssi in sta_rows:
            sta_counts[sta] += 1
            pcaps_by_sta[sta].add(pcap_name)

            ch = freq_to_channel(freq)
            if ch is not None:
                ch_counts_by_sta[sta][str(ch)] += 1

            if rssi is not None:
                if sta not in best_rssi_by_sta or rssi > best_rssi_by_sta[sta]:
                    best_rssi_by_sta[sta] = rssi

        sta_per_pcap_counts[pcap_name] = sta_counts

        # --- Handshake / EAPOL evidence ---
        eapol_rows = _run_tshark_eapol_fields(pcap, tshark_exe)
        eapol_per_pcap[pcap_name] = len(eapol_rows)
        if eapol_rows:
            for bssid, _sa, _da, msg_no in eapol_rows:
                if not bssid:
                    continue
                eapol_by_bssid[bssid] += 1
                if msg_no is not None and 1 <= msg_no <= 4:
                    msg_seen_by_bssid[bssid].add(msg_no)

    # Build handshake confidence map.
    handshake_conf: Dict[str, str] = {}
    for b in set(list(eapol_by_bssid.keys()) + list(msg_seen_by_bssid.keys())):
        msgs = msg_seen_by_bssid.get(b, set())
        if {1, 2, 3, 4}.issubset(msgs):
            handshake_conf[b] = "4WAY"
        elif msgs:
            handshake_conf[b] = "PARTIAL"
        elif eapol_by_bssid.get(b, 0) > 0:
            handshake_conf[b] = "EAPOL"
        else:
            handshake_conf[b] = "NONE"

    return (
        ap_bssids,
        ap_per_pcap_counts,
        sta_per_pcap_counts,
        ssid_counts_by_bssid,
        ch_counts_by_ap,
        best_rssi_by_ap,
        ch_counts_by_sta,
        best_rssi_by_sta,
        pcaps_by_ap,
        pcaps_by_sta,
        eapol_per_pcap,
        dict(eapol_by_bssid),
        handshake_conf,
        "tshark OK",
    )


def _html_table(headers: List[str], rows: List[Tuple]) -> str:
    th = "".join([f"<th>{escape(str(h))}</th>" for h in headers])
    body = "".join(
        ["<tr>" + "".join([f"<td>{escape(str(x))}</td>" for x in r]) + "</tr>" for r in rows]
    )
    return f"<table><tr>{th}</tr>{body}</table>"


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
    """
    PCAP evidence reports (preferred v0.3C look):
      - pcap_bssid_master.csv/.xlsx (AP BSSIDs)
      - pcap_per_file_summary.csv
      - pcap_summary.html (AP + Stations + All Roles Top 50)
    """
    oui_db, oui_src, oui_entries = load_oui_db()

    # -----------------------------
    # Master table (one row per AP BSSID)
    # -----------------------------
    master_rows: List[dict] = []
    for bssid in sorted(ap_bssids):
        # choose most common SSID for display; keep all in CSV
        ssid_counter = ssid_counts_by_bssid.get(bssid, Counter())
        ssids_sorted = [s for s, _n in ssid_counter.most_common()]
        ssids_csv = ", ".join(ssids_sorted) if ssids_sorted else NO_DATA

        frames = sum(counts.get(bssid, 0) for counts in ap_per_pcap_counts.values())
        eapol_frames = int(eapol_by_bssid.get(bssid, 0)) if isinstance(eapol_by_bssid, dict) else 0
        hs_seen = "Yes" if eapol_frames > 0 else "No"
        hs_conf = handshake_conf_by_bssid.get(bssid, "EAPOL" if eapol_frames > 0 else "NONE") if isinstance(handshake_conf_by_bssid, dict) else ("EAPOL" if eapol_frames > 0 else "NONE")
        master_rows.append(
            {
                "BSSID": bssid,
                "SSID(s)": ssids_csv,
                "Frames": frames,
                "HandshakeSeen": hs_seen,
                "HandshakeConfidence": hs_conf,
                "EAPOLFrames": eapol_frames,
                "HandshakePCAPFiles": ", ".join(sorted(list(pcaps_by_ap.get(bssid, set())))) if (eapol_frames > 0 and pcaps_by_ap.get(bssid)) else NO_DATA,
                "PCAPFiles": ", ".join(sorted(list(pcaps_by_ap.get(bssid, set())))) if pcaps_by_ap.get(bssid) else NO_DATA,
                "MatchedInLogs": "Yes" if bssid in all_log_macs else "No",
            }
        )

    master_rows.sort(key=lambda r: int(r.get("Frames", 0)), reverse=True)

    master_csv = write_csv(master_rows, outdir, "pcap_bssid_master.csv")
    master_xlsx = write_xlsx(master_rows, outdir, "pcap_bssid_master.xlsx")

    # -----------------------------
    # Per file summary (AP + Station)
    # -----------------------------
    per_rows: List[dict] = []
    for pcap_name in sorted(set(list(ap_per_pcap_counts.keys()) + list(sta_per_pcap_counts.keys()))):
        ap_counts = ap_per_pcap_counts.get(pcap_name, Counter())
        sta_counts = sta_per_pcap_counts.get(pcap_name, Counter())

        ap_uniq = len(ap_counts)
        ap_frames = sum(ap_counts.values())
        ap_matched = len(set(ap_counts.keys()) & all_log_macs)
        ap_pct = round((ap_matched / ap_uniq) * 100.0, 1) if ap_uniq else 0.0

        sta_uniq = len(sta_counts)
        sta_frames = sum(sta_counts.values())

        eapol_frames = int(eapol_per_pcap.get(pcap_name, 0)) if isinstance(eapol_per_pcap, dict) else 0
        hs_present = "Yes" if eapol_frames > 0 else "No"

        per_rows.append(
            {
                "PCAP": pcap_name,
                "AP_Frames": ap_frames,
                "AP_UniqueBSSIDs": ap_uniq,
                "AP_MatchedInLogs": ap_matched,
                "AP_MatchPct": f"{ap_pct}%",
                "Station_Frames": sta_frames,
                "Station_UniqueMACs": sta_uniq,
                "HandshakePresent": hs_present,
                "EAPOL_Frames": eapol_frames,
            }
        )

    per_csv = write_csv(per_rows, outdir, "pcap_per_file_summary.csv")

    # -----------------------------
    # Build Top 50 tables
    # -----------------------------
    # AP Top 50 by frames
    ap_top50 = master_rows[:50]
    ap_rows_tbl: List[Tuple] = []
    for r in ap_top50:
        bssid = r["BSSID"]
        ssid_counter = ssid_counts_by_bssid.get(bssid, Counter())
        # pick most common SSID for display
        best_ssid = ssid_counter.most_common(1)[0][0] if ssid_counter else NO_DATA
        ssid_disp = ssid_ascii_hex_display(best_ssid)

        ch_mode = NO_DATA
        if bssid in ch_counts_by_ap and ch_counts_by_ap[bssid]:
            ch_mode = ch_counts_by_ap[bssid].most_common(1)[0][0]

        best_rssi = best_rssi_by_ap.get(bssid, NO_DATA)
        vendor = vendor_for(bssid, oui_db)
        cat = category_guess("AP", vendor, is_locally_administered(bssid))
        hs_seen = r.get("HandshakeSeen", "No")
        hs_conf = r.get("HandshakeConfidence", "NONE")
        eapol_frames = r.get("EAPOLFrames", 0)
        ap_rows_tbl.append(
            (bssid, ssid_disp, r["Frames"], r["MatchedInLogs"], hs_seen, hs_conf, eapol_frames, ch_mode, best_rssi, vendor, cat)
        )

    # Stations Top 50 by frames
    sta_totals = Counter()
    for counts in sta_per_pcap_counts.values():
        sta_totals.update(counts)

    sta_rows_tbl: List[Tuple] = []
    for sta, frames in sta_totals.most_common(50):
        ch_mode = NO_DATA
        if sta in ch_counts_by_sta and ch_counts_by_sta[sta]:
            ch_mode = ch_counts_by_sta[sta].most_common(1)[0][0]
        best_rssi = best_rssi_by_sta.get(sta, NO_DATA)
        vendor = vendor_for(sta, oui_db)
        loc = "Yes" if is_locally_administered(sta) else "No"
        cat = category_guess("STA", vendor, is_locally_administered(sta))
        sta_rows_tbl.append((sta, frames, ch_mode, best_rssi, vendor, loc, cat))

    # All roles Top 50
    all_totals = Counter()
    # AP contributions
    for r in master_rows:
        all_totals[r["BSSID"]] += int(r.get("Frames", 0))
    # STA contributions
    for sta, frames in sta_totals.items():
        all_totals[sta] += frames

    all_rows_tbl: List[Tuple] = []
    for mac, frames in all_totals.most_common(50):
        roles = []
        if mac in ap_bssids:
            roles.append("AP")
        if mac in sta_totals:
            roles.append("Station")
        role_str = "+".join(roles) if roles else "Unknown"

        vendor = vendor_for(mac, oui_db)
        loc = "Yes" if is_locally_administered(mac) else "No"
        # "observed role" if AP present
        cat = category_guess("AP" if "AP" in roles else "STA", vendor, is_locally_administered(mac))

        all_rows_tbl.append((mac, role_str, frames, vendor, loc, cat))

    # -----------------------------
    # HTML report (restored style)
    # -----------------------------
    html_path = os.path.join(outdir, "pcap_summary.html")
    per_tbl = [
        (
            r["PCAP"],
            r["AP_Frames"],
            r["AP_UniqueBSSIDs"],
            r["AP_MatchedInLogs"],
            r["AP_MatchPct"],
            r["Station_Frames"],
            r["Station_UniqueMACs"],
            r.get("HandshakePresent", "No"),
            r.get("EAPOL_Frames", 0),
        )
        for r in per_rows
    ]

    version = "0.3C.4"
    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8"/>
<title>PCAP Evidence Report</title>
<style>
  body {{ background:black; color:limegreen; font-family:Consolas, monospace; padding:20px; }}
  h1,h2 {{ color:#00ffcc; text-shadow:0 0 6px #00ffcc; }}
  table {{ border-collapse:collapse; width:100%; margin:12px 0; }}
  th,td {{ border:1px solid limegreen; padding:6px; vertical-align: top; }}
  a {{ color: cyan; text-decoration:none; }}
  a:hover {{ text-decoration:underline; }}
  .notes {{ color:#A0FFA0; font-style:italic; }}
</style>
</head>
<body>

<div style="padding:10px; border:1px solid limegreen; margin-bottom:12px;">
  <b>Navigate:</b>
  <a href="summary.html">Summary</a> |
  <a href="map.html">Map</a> |
  <a href="pcap_summary.html">PCAP Evidence</a>
</div>

<h1>PCAP Evidence Report</h1>
<p><b>Version:</b> {escape(version)} | Generated: {escape(now_str())}</p>
<p><b>Parser status:</b> {escape(status)}</p>
<p><b>OUI DB:</b> IEEE oui.csv | entries={oui_entries}<br><b>OUI Source:</b> {escape(oui_src)}</p>

<h2>What this report means</h2>
<ul>
  <li><b>AP section</b> (Access Points): built mainly from <b>beacons</b> and <b>probe responses</b>. This is strong evidence a network existed on-air.</li>
  <li><b>Stations section</b> (Clients): built from <b>probe requests</b> and <b>association/reassociation requests</b>. This shows nearby devices searching or joining networks.</li>
  <li><b>All Roles</b>: combines both lists into one “what was active in the air” leaderboard.</li>
  <li><b>Device category guesses</b> are vendor-based and labeled as guesses unless the role is directly observed (AP).</li>
</ul>

<h2>Per-PCAP Summary</h2>
{_html_table(["PCAP","AP_Frames","AP_UniqueBSSIDs","AP_MatchedInLogs","AP_MatchPct","Station_Frames","Station_UniqueMACs","Handshake","EAPOL Frames"], per_tbl)}

<h2>Top 50 Access Points (unique BSSIDs) by Frames</h2>
{_html_table(["BSSID","SSID (ASCII/HEX)","Frames","MatchedInLogs","Handshake","HS Confidence","EAPOL Frames","Ch(mode)","BestRSSI","Vendor","CategoryGuess"], ap_rows_tbl)}

<h2>Top 50 Stations/Clients by Frames</h2>
{_html_table(["StationMAC","Frames","Ch(mode)","BestRSSI","Vendor","LocallyAdmin?","CategoryGuess"], sta_rows_tbl)}

<h2>Top 50 Devices (All Roles) by Frames</h2>
{_html_table(["MAC","RolesObserved","Frames","Vendor","LocallyAdmin?","CategoryGuess"], all_rows_tbl)}

<p class="notes">
If channel/RSSI shows <b>No Data</b>, your capture adapter/driver likely didn’t record it.
We fall back from frequency → channel when possible.
</p>

<p class="notes">
Stations often use randomized MACs. When <b>LocallyAdmin? = Yes</b>, vendor and device-type guesses become unreliable.
</p>

<p class="notes">
If AP totals are 0 but you know the capture has beacons, a common cause is that <b>tshark is not visible in PATH</b>
for the Python/EXE process. Try running: <code>tshark -v</code> in the same PowerShell session you launch the app from.
</p>
</body>
</html>
"""
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    return {
        "pcap_master_csv": master_csv,
        "pcap_master_xlsx": master_xlsx if master_xlsx else NO_DATA,
        "pcap_per_file_csv": per_csv,
        "pcap_summary_html": html_path,
    }


def _auth_bucket_s3(auth: str) -> str:
    a = (auth or "").upper()
    if "WPA3" in a: return "WPA3"
    if "WPA2" in a: return "WPA2"
    if "WPA"  in a: return "WPA"
    if "WEP"  in a: return "WEP"
    if "OPEN" in a or a in ("", "[]"): return "Open"
    return "Unknown"


# Overhauled version replaces the stub above at runtime
def write_summary_html(
    centroids: List[dict],
    outdir: str,
    pcap_status: str,
    stats: dict,
) -> str:
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

    oui_db, _oui_src, _oui_entries = load_oui_db()
    def _vend(mac: str) -> str:
        return vendor_for(mac, oui_db)

    sec_counts: Dict[str, int] = {"WPA3": 0, "WPA2": 0, "WPA": 0, "WEP": 0, "Open": 0, "Unknown": 0}
    for c in centroids:
        sec_counts[_auth_bucket_s3(c.get("AuthMode", ""))] += 1
    sec_total = max(sum(sec_counts.values()), 1)
    sec_colors = {"WPA3": "#00ff88", "WPA2": "#00ccff", "WPA": "#ffcc00",
                  "WEP": "#ff6600", "Open": "#ff2244", "Unknown": "#666"}
    sec_bars = "".join(
        f'<div class="seg" style="width:{sec_counts[k]/sec_total*100:.1f}%;background:{col}" '
        f'title="{k}: {sec_counts[k]}">'
        f'<span class="seglabel">{k} {sec_counts[k]/sec_total*100:.1f}%</span></div>'
        for k, col in sec_colors.items() if sec_counts[k]
    )
    sec_legend = " ".join(
        f'<span style="color:{col}">&#9632; {k} ({sec_counts[k]})</span>'
        for k, col in sec_colors.items() if sec_counts[k]
    )

    hs_conf_color = {"FULL": "#00ff88", "PARTIAL": "#ffcc00", "PMKID": "#00ccff"}
    handshake_rows = sorted(
        [c for c in centroids if (c.get("HandshakeSeen") or "").strip().lower() == "yes"],
        key=lambda c: {"FULL": 0, "PARTIAL": 1, "PMKID": 2}.get(
            str(c.get("HandshakeConfidence", "")).upper(), 3)
    )

    def _hs_row(c: dict) -> str:
        conf = str(c.get("HandshakeConfidence", "EAPOL")).upper()
        col  = hs_conf_color.get(conf, "#ff9944")
        mac  = escape(c.get("MAC", ""))
        ssid = escape(c.get("TopSSID", "No Data"))
        eapol = escape(str(c.get("EAPOLFrames", 0)))
        files = escape(str(c.get("HandshakePCAPFiles", "No Data")))
        lat   = c.get("CentroidLat", "")
        lon   = c.get("CentroidLon", "")
        coord = f'data-lat="{lat}" data-lon="{lon}"' if lat not in (NO_DATA, "", None) else ""
        v     = escape(_vend(c.get("MAC", "")))
        return (
            f'<tr class="hs-row" data-mac="{mac}" data-ssid="{ssid}" data-vendor="{v}" {coord}>'
            f'<td><b style="color:{col}">{conf}</b></td>'
            f'<td>{mac}</td><td>{ssid}</td><td>{eapol}</td>'
            f'<td style="font-size:0.8em;max-width:200px;overflow:hidden;text-overflow:ellipsis">{files}</td>'
            f'</tr>'
        )

    hs_table_rows = "".join(_hs_row(c) for c in handshake_rows[:200])

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
            strips.append(
                f'<div class="hstrip" style="background:rgb(0,{g},60);opacity:{0.3+inten*0.7:.2f}" '
                f'title="{escape(h)}: {hour_buckets[h]} networks"></div>'
            )
        timeline_html = (
            '<div id="timeline-wrap">'
            f'<div id="timeline">{"".join(strips)}</div>'
            f'<div class="tl-label">{len(sorted_hrs)} hour buckets &nbsp;'
            f'{escape(sorted_hrs[0])} &rarr; {escape(sorted_hrs[-1])}</div>'
            "</div>"
        )

    vendor_counts: _Counter = _Counter()
    for c in centroids:
        vendor_counts[_vend(c.get("MAC", ""))] += 1
    top_vendors = vendor_counts.most_common(25)
    vendor_total = max(sum(v for _, v in top_vendors), 1)
    treemap_cells = "".join(
        f'<div class="tm-cell" style="flex:{cnt/vendor_total*100:.2f};'
        f'background:hsl({int((i*137.5)%360)},55%,16%);'
        f'border:1px solid hsl({int((i*137.5)%360)},75%,32%)" '
        f'data-vendor="{escape(vname)}" title="{escape(vname)}: {cnt}">'
        f'<span class="tm-name">{escape(vname)}</span>'
        f'<span class="tm-count">{cnt}</span></div>'
        for i, (vname, cnt) in enumerate(top_vendors)
    )

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
            "vendor": _vend(c.get("MAC", "")),
            "lat": str(lat) if lat not in (NO_DATA, "", None) else "",
            "lon": str(lon) if lon not in (NO_DATA, "", None) else "",
            "first": str(c.get("FirstSeen", NO_DATA)),
            "last": str(c.get("LastSeen", NO_DATA)),
        })
    table_json = _json.dumps(table_data, ensure_ascii=False)

    stat_pairs = [
        ("Total Unique Networks (from PCAP)", stats.get("pcap_unique", 0)),
        ("Unique MACs Across Logs", stats.get("log_unique", 0)),
        ("PCAP parser status", pcap_status),
        ("Networks with Locations (Centroids)", stats.get("centroid_with_loc", 0)),
        ("Total Raw Sightings (from All Logs)", stats.get("raw_sightings", 0)),
        ("Networks with Handshakes", len(handshake_rows)),
        ("PCAP ↔ Log Matches (MAC/BSSID overlap)", stats.get("overlap_text", "—")),
        ("Avg Sightings per MAC", stats.get("avg_sightings", 0)),
        ("RSSI Range (dBm)", stats.get("rssi_range", "—")),
        ("Location Cluster (bounds)", stats.get("bounds_str", "—")),
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
#net-tbl th:hover{{color:var(--fg2)}} #net-tbl th.sorted{{color:var(--fg2)}}
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
      <th data-c="ssid">SSID &#x25BC;</th><th data-c="mac">MAC &#x25BC;</th>
      <th data-c="vendor">Vendor &#x25BC;</th><th data-c="auth">Security &#x25BC;</th>
      <th data-c="ch">Ch &#x25BC;</th><th data-c="rssi">RSSI &#x25BC;</th>
      <th data-c="sightings">Seen &#x25BC;</th><th data-c="risk">Risk &#x25BC;</th>
      <th data-c="hs">HS &#x25BC;</th><th data-c="quality">Loc &#x25BC;</th>
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
    <li><a href="pcap_summary.html">pcap_summary.html</a> — full PCAP analysis</li>
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
  if(a.indexOf("WPA3")>=0)return"a-wpa3";if(a.indexOf("WPA2")>=0)return"a-wpa2";
  if(a.indexOf("WPA")>=0)return"a-wpa";if(a.indexOf("WEP")>=0)return"a-wep";
  if(a.indexOf("OPEN")>=0)return"a-open";return"";
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
    html+='<td title="'+esc(r.ssid)+'">'+esc(r.ssid)+'</td><td>'+esc(r.mac)+'</td>';
    html+='<td title="'+esc(r.vendor)+'">'+esc(r.vendor.substring(0,22))+'</td>';
    html+='<td class="'+ac+'">'+esc(r.auth)+'</td>';
    html+='<td>'+esc(r.ch)+'</td><td>'+esc(r.rssi)+'</td><td>'+esc(r.sightings)+'</td>';
    html+='<td class="'+rc+'">'+esc(r.risk)+'</td>';
    html+='<td class="'+hc+'">'+esc(r.hs)+'</td><td>'+esc(r.quality)+'</td></tr>';
  }});
  tbody.innerHTML=html;
  document.getElementById("rc").textContent=
    filtered.length.toLocaleString()+" networks"+(activeVendor?" ["+activeVendor+"]":"");
  renderPages();
}}
function renderPages(){{
  var pages=Math.ceil(filtered.length/PAGE);
  var el=document.getElementById("pagination");
  var html='<span style="color:#557;font-size:0.84em">Page '+curPage+'/'+pages+'</span> ';
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
    th.classList.add("sorted");sortRows();
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
  }});else{{var ta=document.createElement("textarea");ta.value=txt;
    document.body.appendChild(ta);ta.select();document.execCommand("copy");ta.remove();}}
}}
document.getElementById("cc-mac").addEventListener("click",function(){{if(ctxRow)cp(ctxRow.dataset.mac||"");hideCtx();}});
document.getElementById("cc-ssid").addEventListener("click",function(){{if(ctxRow)cp(ctxRow.dataset.ssid||"");hideCtx();}});
document.getElementById("cc-coords").addEventListener("click",function(){{
  if(!ctxRow)return;var lat=ctxRow.dataset.lat,lon=ctxRow.dataset.lon;
  cp(lat&&lon?lat+","+lon:"No coordinates");hideCtx();
}});
document.getElementById("cc-osm").addEventListener("click",function(){{
  if(!ctxRow)return;var lat=ctxRow.dataset.lat,lon=ctxRow.dataset.lon;
  if(lat&&lon)window.open("https://www.openstreetmap.org/?mlat="+lat+"&mlon="+lon+"&zoom=17","_blank");
  hideCtx();
}});
document.getElementById("cc-vendor").addEventListener("click",function(){{
  if(!ctxRow)return;var v=ctxRow.dataset.vendor||"";
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



# -----------------------------
# Project Mode (Step 3C)
# -----------------------------
def _read_json(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _write_json(path: str, data: dict) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


def ensure_project_and_create_run(project_dir: str, wardrive_files: List[str], pcap_files: List[str]) -> Tuple[str, str, dict]:
    """
    Option 2 (Project + Run Index):
      - project_dir/
          project.json
          index.html
          runs/
              run_001/
              run_002/
              ...
    Returns:
      (project_dir, run_dir, run_meta)
    """
    os.makedirs(project_dir, exist_ok=True)
    runs_root = os.path.join(project_dir, "runs")
    os.makedirs(runs_root, exist_ok=True)

    manifest_path = os.path.join(project_dir, "project.json")
    manifest = _read_json(manifest_path)
    if "runs" not in manifest or not isinstance(manifest.get("runs"), list):
        manifest = {
            "schema_version": 1,
            "created": now_str(),
            "runs": [],
            "notes": "Wardrive Analyzer Project. Each run is isolated to prevent overwrites.",
        }

    # Determine next run number (prefer manifest; fallback to directory scan)
    next_n = 1
    try:
        if manifest["runs"]:
            nums = []
            for r in manifest["runs"]:
                name = str(r.get("run_name", ""))
                m = re.match(r"run_(\d+)", name)
                if m:
                    nums.append(int(m.group(1)))
            if nums:
                next_n = max(nums) + 1
    except Exception:
        next_n = 1

    # If manifest missing/old, scan filesystem too (defensive)
    try:
        for entry in os.listdir(runs_root):
            m = re.match(r"run_(\d+)", entry)
            if m:
                next_n = max(next_n, int(m.group(1)) + 1)
    except Exception:
        pass

    run_name = f"run_{next_n:03d}"
    run_dir = os.path.join(runs_root, run_name)
    os.makedirs(run_dir, exist_ok=False)

    # Light-touch input fingerprints (educational + reproducible; not privacy-invasive)
    def _file_meta(p: str) -> dict:
        try:
            st = os.stat(p)
            return {
                "name": os.path.basename(p),
                "size": st.st_size,
                "mtime": datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds"),
            }
        except Exception:
            return {"name": os.path.basename(p)}

    run_meta = {
        "run_name": run_name,
        "created": now_str(),
        "wardrive_inputs": [_file_meta(p) for p in wardrive_files],
        "pcap_inputs": [_file_meta(p) for p in pcap_files],
        "output_rel": f"runs/{run_name}",
        "artifacts": {},  # filled after analysis
    }

    manifest["runs"].append(run_meta)
    _write_json(manifest_path, manifest)

    return project_dir, run_dir, run_meta


def update_project_index(project_dir: str) -> str:
    """
    Creates/updates a simple project index page listing all runs.
    This is intentionally static HTML (no dependencies, works offline).
    """
    manifest_path = os.path.join(project_dir, "project.json")
    manifest = _read_json(manifest_path)
    runs = manifest.get("runs", []) if isinstance(manifest.get("runs"), list) else []

    # Newest first
    runs = list(reversed(runs))

    rows = []
    for r in runs:
        run_name = escape(str(r.get("run_name", "run")))
        created = escape(str(r.get("created", "")))
        out_rel = str(r.get("output_rel", ""))
        artifacts = r.get("artifacts", {}) if isinstance(r.get("artifacts"), dict) else {}

        def _link(label: str, fname_key: str, default: str) -> str:
            fname = artifacts.get(fname_key, default)
            if not fname or fname == NO_DATA:
                return escape(label) + ": " + escape(NO_DATA)
            href = f"{out_rel}/{fname}".replace("\\", "/")
            return f'<a href="{escape(href)}">{escape(label)}</a>'

        links = [
            _link("Summary", "summary", "summary.html"),
            _link("Map", "map", "map.html"),
            _link("Master CSV", "csv", "wardrive_master.csv"),
            _link("PCAP Summary", "pcap_summary_html", "pcap_summary.html"),
        ]
        rows.append((run_name, created, " | ".join(links)))

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8"/>
<title>Wardrive Project Index</title>
<style>
  body {{ background:black; color:limegreen; font-family:Consolas, monospace; padding:20px; }}
  h1 {{ color:#00ffcc; text-shadow:0 0 6px #00ffcc; }}
  table {{ border-collapse:collapse; width:100%; margin-top:12px; }}
  th,td {{ border:1px solid limegreen; padding:8px; vertical-align:top; }}
  a {{ color: cyan; text-decoration:none; }}
  a:hover {{ text-decoration: underline; }}
  .muted {{ color:#A0FFA0; }}
</style>
</head>
<body>
<h1>WARDIVE PROJECT — Run History</h1>
<p class="muted">This page is auto-generated. Each run is isolated in <code>runs/</code> to prevent overwrites.</p>
<p class="muted">Open the newest run’s <b>Summary</b> first; it explains how to interpret the data.</p>

<table>
<tr><th>Run</th><th>Created</th><th>Artifacts</th></tr>
{''.join([f"<tr><td>{a}</td><td>{b}</td><td>{c}</td></tr>" for a,b,c in rows])}
</table>

</body>
</html>
"""
    index_path = os.path.join(project_dir, "index.html")
    with open(index_path, "w", encoding="utf-8") as f:
        f.write(html)
    return index_path
# -----------------------------
# Main entry used by GUI
# -----------------------------

# -----------------------------
# Main entry used by GUI
# -----------------------------
def _analyze_to_outdir(wardrive_files: List[str], pcap_files: List[str], outdir: str, status_cb: Optional[Callable[[str], None]] = None) -> dict:
    """
    Called by GUI.

    Step 3C (Project mode):
      - Treats `outdir` as a PROJECT folder (not a single-run folder)
      - Creates a new isolated run folder under outdir/runs/run_###
      - Updates outdir/index.html with clickable run history
      - Updates outdir/project.json manifest

    Produces all artifacts inside the run folder and returns absolute paths.
    """
    # 0) Project + new run (prevents overwrites)
    project_dir, run_dir, run_meta = ensure_project_and_create_run(outdir, wardrive_files, pcap_files)
    # 0.5) Stage commentary: explain what we are about to parse (educational + confidence)
    log_explain = {
        "wardrive": "GPS + Wi-Fi sightings from wardrive mode. This is what places BSSIDs onto the map.",
        "station_wardrive": "Client sightings captured during wardrive. Helps correlate stations seen near APs.",
        "arpscan": "LAN reminder: ARP scan results (non-Wi-Fi). Useful for local network device clues.",
        "dns": "DNS requests/responses seen by the device (non-Wi-Fi). Helps identify what devices were trying to reach.",
        "http": "HTTP observations (non-Wi-Fi). Can reveal hostnames/paths in cleartext (if present).",
        "https": "HTTPS observations (non-Wi-Fi). Usually metadata only; still helpful for timing and correlation.",
        "pingscan": "Ping sweep results. Useful for discovering live hosts in a subnet.",
        "portscan": "Port scan results. Shows which hosts had open ports at capture time.",
        "sshscan": "SSH scan results. Indicates hosts offering SSH.",
        "telnetscan": "Telnet scan results. Indicates hosts offering Telnet.",
    }
    pcap_explain = {
        "beacon": "Beacon frames: AP advertisements. Best for identifying networks + security capabilities.",
        "probe": "Probe traffic: clients searching for networks + some AP responses.",
        "ap": "AP-focused capture. Usually beacons/probe responses; good AP inventory.",
        "ap_sta": "AP+Station capture. Helps correlate AP ↔ client activity.",
        "station": "Station/client-focused capture. Good for nearby client devices and probe SSIDs.",
        "deauth": "Deauth/disassoc frames. Usually not handshake material, but shows activity and disruption events.",
        "sae_commit": "SAE (WPA3) commit frames. Can indicate WPA3 negotiations.",
        "packet_monitor": "Mixed monitor capture. Often where handshake/EAPOL frames appear.",
        "raw": "Raw mixed capture. Often where handshake/EAPOL frames appear.",
        "multissid": "Multi-SSID/variety capture. Can contain mixed management traffic.",
    }

    _emit_stage_groups(status_cb, "Evidence Intake — Logs (GPS / device evidence)", wardrive_files, log_explain)
    _emit_stage_groups(status_cb, "Evidence Intake — PCAPs (radio evidence)", pcap_files, pcap_explain)



    # 1) Load GPS evidence (logs)
    _emit(status_cb, "Parsing wardrive logs (GPS evidence)…")
    sightings_by_mac, logfiles_by_mac = load_wardrive_logs(wardrive_files, status_cb=status_cb)
    raw_sightings = sum(len(v) for v in sightings_by_mac.values())
    all_log_macs = set(sightings_by_mac.keys())

    # 2) Load radio evidence (PCAP via tshark)
    _emit(status_cb, "Parsing PCAPs (radio evidence)…")
    (
        ap_bssids,
        ap_per_pcap_counts,
        sta_per_pcap_counts,
        ssid_counts_by_bssid,
        ch_counts_by_ap,
        best_rssi_by_ap,
        ch_counts_by_sta,
        best_rssi_by_sta,
        pcaps_by_ap,
        pcaps_by_sta,
        eapol_per_pcap,
        eapol_by_bssid,
        handshake_conf_by_bssid,
        pcap_status,
    ) = load_pcaps_tshark(pcap_files, status_cb=status_cb)

    # 3) Build centroid master table
    centroids_rows: List[dict] = []
    centroid_points: List[Tuple[float, float]] = []

    for mac, sights in sightings_by_mac.items():
        ssids = [s.ssid for s in sights if s.ssid not in (None, "", NO_DATA)]
        top_ssid = Counter(ssids).most_common(1)[0][0] if ssids else NO_DATA

        auths = [s.auth for s in sights if s.auth not in (None, "", NO_DATA)]
        auth_mode = Counter(auths).most_common(1)[0][0] if auths else NO_DATA

        chans = [s.channel for s in sights if s.channel not in (None, "", NO_DATA)]
        chan_mode = Counter(chans).most_common(1)[0][0] if chans else NO_DATA

        mac_rssi = [s.rssi for s in sights if s.rssi is not None]
        best_rssi = max(mac_rssi) if mac_rssi else None
        avg_rssi = round(sum(mac_rssi) / len(mac_rssi), 1) if mac_rssi else None

        clat, clon, conf_m, used_n = compute_centroid_and_confidence(sights)
        if clat is not None and clon is not None:
            centroid_points.append((clat, clon))

        stab = stability_score(conf_m, used_n or 0) if conf_m is not None else 0
        seen_in_pcap = "Yes" if mac in ap_bssids else "No"
        eapol_frames = int(eapol_by_bssid.get(mac, 0)) if isinstance(eapol_by_bssid, dict) else 0
        hs_conf = "NONE"
        if isinstance(handshake_conf_by_bssid, dict):
            hs_conf = handshake_conf_by_bssid.get(mac, "EAPOL" if eapol_frames > 0 else "NONE")
        hs_seen = "Yes" if eapol_frames > 0 else "No"
        risk = compute_risk(auth_mode, top_ssid, best_rssi)

        centroids_rows.append(
            {
                "MAC": mac,
                "TopSSID": top_ssid,
                "SSIDCount": len(set(ssids)) if ssids else 0,
                "AuthMode": auth_mode,
                "Channel": chan_mode,
                "HandshakeSeen": hs_seen,
                "HandshakeConfidence": hs_conf,
                "EAPOLFrames": eapol_frames,
                "HandshakePCAPFiles": ", ".join(sorted(list(pcaps_by_ap.get(mac, set())))) if (eapol_frames > 0 and pcaps_by_ap.get(mac)) else NO_DATA,
                "Sightings": len(sights),
                "UsedForCentroid": used_n if used_n is not None else 0,
                "BestRSSI": best_rssi if best_rssi is not None else NO_DATA,
                "AvgRSSI": avg_rssi if avg_rssi is not None else NO_DATA,
                "CentroidLat": round(clat, 7) if clat is not None else NO_DATA,
                "CentroidLon": round(clon, 7) if clon is not None else NO_DATA,
                "ConfidenceRadiusM": round(conf_m, 1) if conf_m is not None else NO_DATA,
                "Stability": stab,
                "RiskScore": risk,
                "SeenInPCAP": seen_in_pcap,
                "PCAPFiles": ", ".join(sorted(list(pcaps_by_ap.get(mac, set())))) if pcaps_by_ap.get(mac) else NO_DATA,
                "LogFiles": ", ".join(sorted(list(logfiles_by_mac.get(mac, set())))) if logfiles_by_mac.get(mac) else NO_DATA,
            }
        )

    # Sort: highest risk first
    centroids_rows.sort(key=lambda r: (r.get("RiskScore", 0), r.get("Sightings", 0)), reverse=True)

    # Stats
    pcap_unique = len(ap_bssids)
    log_unique = len(all_log_macs)
    overlap = len(all_log_macs & ap_bssids)
    overlap_pct = round((overlap / pcap_unique) * 100.0, 1) if pcap_unique else 0.0
    overlap_pct_logs = round((overlap / log_unique) * 100.0, 1) if log_unique else 0.0
    overlap_text = f"{overlap} ({overlap_pct}% of PCAP BSSIDs; {overlap_pct_logs}% of log MACs)"

    rssi_vals = [s.rssi for v in sightings_by_mac.values() for s in v if s.rssi is not None]
    if rssi_vals:
        rssi_min = min(rssi_vals)
        rssi_max = max(rssi_vals)
        rssi_avg = round(sum(rssi_vals) / len(rssi_vals), 1)
        rssi_range = f"{rssi_min} (weak) to {rssi_max} (strong); Avg: {rssi_avg}"
    else:
        rssi_range = NO_DATA

    if centroid_points:
        lats = [p[0] for p in centroid_points]
        lons = [p[1] for p in centroid_points]
        bounds_str = f"{min(lats):.5f}-{max(lats):.5f} lat, {min(lons):.5f}-{max(lons):.5f} lon"
    else:
        bounds_str = NO_DATA

    stats = {
        "pcap_unique": pcap_unique,
        "log_unique": log_unique,
        "centroid_with_loc": sum(1 for r in centroids_rows if r.get("CentroidLat") not in (NO_DATA, "", None)),
        "raw_sightings": raw_sightings,
        "overlap_text": overlap_text,
        "avg_sightings": round(raw_sightings / log_unique, 2) if log_unique else 0,
        "rssi_range": rssi_range,
        "bounds_str": bounds_str,
    }

    # 4) Write outputs (INSIDE THE RUN FOLDER)
    _emit(status_cb, "[+] WR1T1NG: wardrive_master.csv")
    csv_path = write_csv(centroids_rows, run_dir, "wardrive_master.csv")
    _emit(status_cb, "[+] WR1T1NG: wardrive_master.xlsx")
    xlsx_path = write_xlsx(centroids_rows, run_dir, "wardrive_master.xlsx")
    _emit(status_cb, "[+] WR1T1NG: wardrive_map.kml")
    kml_path = write_kml(centroids_rows, run_dir)
    _emit(status_cb, "[+] R3ND3R1NG: map.html")
    map_path = write_map_html(centroids_rows, run_dir, circles_enabled_default=False)

    # PCAP outputs
    _emit(status_cb, "[*] G3N3R4T1NG PCAP R3P0RTS…")
    pcap_artifacts = write_pcap_reports(
        outdir=run_dir,
        ap_bssids=ap_bssids,
        ap_per_pcap_counts=ap_per_pcap_counts,
        sta_per_pcap_counts=sta_per_pcap_counts,
        ssid_counts_by_bssid=ssid_counts_by_bssid,
        ch_counts_by_ap=ch_counts_by_ap,
        best_rssi_by_ap=best_rssi_by_ap,
        ch_counts_by_sta=ch_counts_by_sta,
        best_rssi_by_sta=best_rssi_by_sta,
        pcaps_by_ap=pcaps_by_ap,
        pcaps_by_sta=pcaps_by_sta,
        eapol_per_pcap=eapol_per_pcap,
        eapol_by_bssid=eapol_by_bssid,
        handshake_conf_by_bssid=handshake_conf_by_bssid,
        all_log_macs=all_log_macs,
        status=pcap_status,
    )

    _emit(status_cb, "[+] R3ND3R1NG: summary.html")
    summary_path = write_summary_html(
        centroids=centroids_rows,
        outdir=run_dir,
        pcap_status=pcap_status,
        stats=stats,
    )

    results = {
        "project_dir": project_dir,
        "run_dir": run_dir,
        "run_name": run_meta.get("run_name", NO_DATA),
        "csv": csv_path,
        "xlsx": xlsx_path if xlsx_path else NO_DATA,
        "kml": kml_path,
        "map": map_path,
        "summary": summary_path,
        **pcap_artifacts,
    }

    # 5) Update manifest artifacts (store filenames only for portability)
    manifest_path = os.path.join(project_dir, "project.json")
    manifest = _read_json(manifest_path)
    try:
        for r in manifest.get("runs", []):
            if r.get("run_name") == results["run_name"]:
                r["artifacts"] = {
                    "csv": os.path.basename(results["csv"]),
                    "xlsx": os.path.basename(results["xlsx"]) if results["xlsx"] != NO_DATA else NO_DATA,
                    "kml": os.path.basename(results["kml"]),
                    "map": os.path.basename(results["map"]),
                    "summary": os.path.basename(results["summary"]),
                    "pcap_master_csv": os.path.basename(results["pcap_master_csv"]),
                    "pcap_master_xlsx": os.path.basename(results["pcap_master_xlsx"]) if results["pcap_master_xlsx"] != NO_DATA else NO_DATA,
                    "pcap_per_file_csv": os.path.basename(results["pcap_per_file_csv"]),
                    "pcap_summary_html": os.path.basename(results["pcap_summary_html"]),
                }
                break
        _write_json(manifest_path, manifest)
    except Exception:
        # Never fail a run just because indexing failed
        pass

    # 6) Update project index.html
    index_path = update_project_index(project_dir)
    results["project_index"] = index_path

    return results


# -----------------------------
# Step 3D: Project-mode wrapper (no overwrite)
# -----------------------------
def _next_run_dir(project_dir: str) -> tuple[str, str]:
    """
    Returns (run_dir, run_id). Creates:
      <project_dir>/runs/run_###_<YYYYMMDD_HHMMSS>/
    """
    os.makedirs(project_dir, exist_ok=True)
    runs_dir = os.path.join(project_dir, "runs")
    os.makedirs(runs_dir, exist_ok=True)

    existing = [d for d in os.listdir(runs_dir) if d.startswith("run_")]
    # Extract numeric prefix if possible
    nums = []
    for d in existing:
        m = re.match(r"run_(\d+)", d)
        if m:
            try:
                nums.append(int(m.group(1)))
            except Exception:
                pass
    n = (max(nums) + 1) if nums else 1
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_id = f"run_{n:03d}_{ts}"
    run_dir = os.path.join(runs_dir, run_id)
    os.makedirs(run_dir, exist_ok=True)
    return run_dir, run_id


def _update_project_manifest(project_dir: str, run_id: str) -> None:
    """
    Writes/updates project.json with basic run history.
    """
    path = os.path.join(project_dir, "project.json")
    data = {"revision": CORE_REVISION, "runs": []}
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
    except Exception:
        data = {"revision": CORE_REVISION, "runs": []}

    data["revision"] = CORE_REVISION
    data.setdefault("runs", [])
    data["runs"].append({"run_id": run_id, "created": datetime.now().isoformat(timespec="seconds")})

    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass


def analyze(
    wardrive_files: List[str],
    pcap_files: List[str],
    project_dir: str,
    status_cb: Optional[Callable[[str], None]] = None,
) -> dict:
    """
    Public entry point for GUI (Project Mode).
    Delegates entirely to _analyze_to_outdir which owns run-folder creation.
    """
    _emit(status_cb, f"[core {CORE_REVISION}] Project folder: {project_dir}")
    results = _analyze_to_outdir(wardrive_files, pcap_files, project_dir, status_cb=status_cb)

    expected = [
        "wardrive_master.csv",
        "wardrive_master.xlsx",
        "wardrive_map.kml",
        "map.html",
        "summary.html",
        "pcap_summary.html",
        "pcap_bssid_master.csv",
        "pcap_bssid_master.xlsx",
        "pcap_per_file_summary.csv",
    ]
    run_dir = results.get("run_dir", project_dir)
    _emit_output_checklist(status_cb, run_dir, expected)

    return results