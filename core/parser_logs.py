"""Parse WigleWifi-1.4 wardrive CSV logs into Sighting dataclasses."""
from __future__ import annotations

import csv
import os
from collections import defaultdict
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Set, Tuple

from .constants import NO_DATA
from .helpers import norm_mac, safe_float, safe_int, safe_str


@dataclass
class Sighting:
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


def load_wardrive_logs(
    files: List[str],
    status_cb: Optional[Callable[[str], None]] = None,
) -> Tuple[Dict[str, List[Sighting]], Dict[str, Set[str]]]:
    """
    Returns:
      - sightings_by_mac: MAC -> list of Sighting
      - logfiles_by_mac:  MAC -> set of log filenames where seen
    """
    sightings_by_mac: Dict[str, List[Sighting]] = defaultdict(list)
    logfiles_by_mac: Dict[str, Set[str]] = defaultdict(set)

    for idx, path in enumerate(files, start=1):
        if status_cb:
            status_cb(f"[*] P4R51NG L0G {idx}/{len(files)}: {os.path.basename(path)}")
        headers: Optional[List[str]] = None
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("WigleWifi"):
                        continue
                    if line.startswith("MAC,"):
                        # Use csv.reader to handle quoted fields correctly
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
            continue

    return sightings_by_mac, logfiles_by_mac
