"""Geospatial computation: centroid, confidence radius, stability, risk."""
from __future__ import annotations

import math
from typing import List, Optional, Tuple

from .constants import (
    RSSI_REF, RSSI_SCALE, ACC_FLOOR_M, ACC_DEFAULT_M, DROP_WEAKEST_FRAC, NO_DATA,
)
from .parser_logs import Sighting
from .helpers import haversine_m


def rssi_weight(rssi: int) -> float:
    return math.exp((rssi - RSSI_REF) / RSSI_SCALE)


def acc_weight(acc_m: Optional[float]) -> float:
    a = acc_m if acc_m is not None else ACC_DEFAULT_M
    return 1.0 / max(a, ACC_FLOOR_M)


def compute_centroid_and_confidence(
    sightings: List[Sighting],
) -> Tuple[Optional[float], Optional[float], Optional[float], Optional[int]]:
    """
    Returns (centroid_lat, centroid_lon, confidence_radius_m, used_points_count).
    """
    valid = [s for s in sightings if s.lat is not None and s.lon is not None and s.rssi is not None]
    if not valid:
        return None, None, None, None

    valid_sorted = sorted(valid, key=lambda s: s.rssi if s.rssi is not None else -999)
    drop_n = int(len(valid_sorted) * DROP_WEAKEST_FRAC)
    kept = valid_sorted[drop_n:] if drop_n < len(valid_sorted) else valid_sorted

    sum_w = sum_lat = sum_lon = 0.0
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
        sum_wd2 += w * (d ** 2)

    rms = math.sqrt(sum_wd2 / sum_w)
    return clat, clon, rms, len(kept)


def stability_score(conf_radius_m: Optional[float], n: int) -> int:
    if conf_radius_m is None or n <= 0:
        return 0
    obs_factor = 1.0 - math.exp(-n / 6.0)
    rad_factor = 1.0 / (1.0 + (conf_radius_m / 50.0))
    return max(0, min(100, int(round(100.0 * obs_factor * rad_factor))))


def compute_risk(auth: str, ssid: str, best_rssi: Optional[int]) -> int:
    """
    Explainable risk score (educational — not a vulnerability score).
      OPEN  +3, WEP +4, legacy WPA +1, hidden SSID +1, strong signal +1
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
