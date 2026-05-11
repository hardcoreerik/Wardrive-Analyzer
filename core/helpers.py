"""Shared utilities: type coercion, MAC normalisation, Haversine, JSON escaping."""
from __future__ import annotations

import math
import os
import sys
from datetime import datetime
from typing import Optional

from .constants import NO_DATA


def resource_path(*parts: str) -> str:
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, *parts)


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
    R = 6_371_000.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * R * math.asin(math.sqrt(a))


def json_str(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


def json_arr(items: list[str]) -> str:
    return "[" + ",".join(items) + "]"


def oui_key(mac: str) -> str:
    parts = (mac or "").upper().split(":")
    return ":".join(parts[:3]) if len(parts) >= 3 else ""


def is_locally_administered(mac: str) -> bool:
    try:
        return (int(mac.split(":")[0], 16) & 0x02) != 0
    except Exception:
        return False
