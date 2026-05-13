"""RF Device DNA: registry, direct frame hints, and capability fingerprints."""
from __future__ import annotations

import csv
import hashlib
import os
import re
import sys
from collections import Counter
from typing import Dict, Iterable, List, Tuple

from .constants import NO_DATA
from .helpers import is_locally_administered

_PRINTABLE_RE = re.compile(r"[\x20-\x7E]+")


def _clean_text(raw: bytes, max_chars: int = 80) -> str:
    text = raw.decode("utf-8", errors="ignore").strip()
    text = "".join(ch for ch in text if ch.isprintable() and ch not in "\r\n\t")
    if not text or not _PRINTABLE_RE.search(text):
        return ""
    return text[:max_chars]


def _hex_prefix(raw: str) -> str:
    return re.sub(r"[^0-9A-F]", "", (raw or "").upper())


def _registry_paths() -> List[str]:
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    root = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
    names = [
        "oui.csv", "mal.csv", "ma-l.csv",
        "mam.csv", "oui28.csv", "ma-m.csv",
        "mas.csv", "oui36.csv", "ma-s.csv", "iab.csv", "cid.csv",
    ]
    paths = []
    for folder in (base, root):
        for name in names:
            path = os.path.normpath(os.path.join(folder, name))
            if path not in paths:
                paths.append(path)
    return paths


def load_registry_db() -> Tuple[Dict[str, Tuple[str, str]], str, int]:
    """Load IEEE registry CSVs if present. Keys are hex prefixes of length 6/7/9."""
    db: Dict[str, Tuple[str, str]] = {}
    sources: List[str] = []
    for path in _registry_paths():
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="ignore", newline="") as f:
                reader = csv.reader(f)
                rows = list(reader)
            if not rows:
                continue
            header = [h.strip().lower() for h in rows[0]]
            if "assignment" not in header:
                continue
            ia = header.index("assignment")
            ireg = header.index("registry") if "registry" in header else None
            iname = header.index("organization name") if "organization name" in header else 1
            for row in rows[1:]:
                if len(row) <= max(ia, iname):
                    continue
                assignment = _hex_prefix(row[ia])
                if len(assignment) not in (6, 7, 9):
                    continue
                registry = row[ireg].strip() if ireg is not None and len(row) > ireg else _registry_from_name(path, assignment)
                org = row[iname].strip() or NO_DATA
                db[assignment] = (registry or _registry_from_name(path, assignment), org)
            sources.append(path)
        except Exception:
            continue
    return db, "; ".join(sources) if sources else NO_DATA, len(db)


def _registry_from_name(path: str, assignment: str) -> str:
    name = os.path.basename(path).lower()
    if "mam" in name or "oui28" in name or "ma-m" in name:
        return "MA-M"
    if "mas" in name or "oui36" in name or "ma-s" in name:
        return "MA-S"
    if "iab" in name:
        return "IAB"
    if "cid" in name:
        return "CID"
    if len(assignment) == 7:
        return "MA-M"
    if len(assignment) == 9:
        return "MA-S"
    return "MA-L"


def lookup_registry(mac: str, registry_db: Dict[str, Tuple[str, str]]) -> Dict[str, str]:
    mac_hex = _hex_prefix(mac)
    if len(mac_hex) < 12:
        return {"RegistryVendor": NO_DATA, "RegistryType": NO_DATA, "RegistryPrefix": NO_DATA}
    for size in (9, 7, 6):
        prefix = mac_hex[:size]
        if prefix in registry_db:
            reg_type, org = registry_db[prefix]
            return {"RegistryVendor": org, "RegistryType": reg_type, "RegistryPrefix": prefix}
    return {"RegistryVendor": NO_DATA, "RegistryType": NO_DATA, "RegistryPrefix": NO_DATA}


def parse_identity_ies(payload: bytes) -> List[str]:
    """Extract compact device identity evidence from 802.11 information elements."""
    evidence: List[str] = []
    i = 0
    while i + 2 <= len(payload):
        ie_id = payload[i]
        ie_len = payload[i + 1]
        start = i + 2
        end = start + ie_len
        if end > len(payload):
            break
        data = payload[start:end]
        if ie_id in (1, 50) and data:
            evidence.append(f"cap:rates={data.hex()[:32]}")
        elif ie_id == 45 and len(data) >= 2:
            evidence.append(f"cap:ht={data[:8].hex()}")
        elif ie_id == 48 and data:
            evidence.append(f"cap:rsn={data[:16].hex()}")
        elif ie_id == 127 and data:
            evidence.append(f"cap:ext={data[:8].hex()}")
        elif ie_id == 191 and len(data) >= 4:
            evidence.append(f"cap:vht={data[:8].hex()}")
        elif ie_id == 255 and data:
            evidence.append(f"cap:extie:{data[0]:02x}={data[1:9].hex()}")
        elif ie_id == 221 and len(data) >= 3:
            oui = ":".join(f"{b:02X}" for b in data[:3])
            subtype = f":{data[3]:02X}" if len(data) >= 4 else ""
            evidence.append(f"vendor_ie:{oui}{subtype}")
            if data[:3] == b"\x00\x50\xF2" and len(data) >= 4 and data[3] == 0x04:
                evidence.extend(_parse_wps_attrs(data[4:]))
        i = end
    return evidence


def _parse_wps_attrs(data: bytes) -> List[str]:
    names = {
        0x1011: "device_name",
        0x1021: "manufacturer",
        0x1023: "model_name",
        0x1024: "model_number",
    }
    evidence: List[str] = []
    i = 0
    while i + 4 <= len(data):
        attr_id = int.from_bytes(data[i:i + 2], "big")
        attr_len = int.from_bytes(data[i + 2:i + 4], "big")
        start = i + 4
        end = start + attr_len
        if end > len(data):
            break
        if attr_id in names:
            text = _clean_text(data[start:end])
            if text:
                evidence.append(f"direct:wps.{names[attr_id]}={text}")
        i = end
    return evidence


def summarize_identity(
    mac: str,
    role: str,
    evidence: Counter,
    registry_db: Dict[str, Tuple[str, str]],
) -> Dict[str, str]:
    reg = lookup_registry(mac, registry_db)
    locally_admin = is_locally_administered(mac)
    direct = _top_values(evidence, "direct:")
    vendor_ies = _top_values(evidence, "vendor_ie:")
    caps = sorted(k for k in evidence if k.startswith("cap:"))
    fingerprint = _fingerprint(caps)

    guess = _hardware_guess(reg["RegistryVendor"], direct, vendor_ies)
    confidence = _confidence(role, locally_admin, reg["RegistryVendor"], direct, vendor_ies, caps)
    evidence_bits = []
    if direct:
        evidence_bits.append("WPS: " + "; ".join(direct[:3]))
    if reg["RegistryVendor"] != NO_DATA:
        evidence_bits.append(f"{reg['RegistryType']} {reg['RegistryPrefix']}")
    if vendor_ies:
        evidence_bits.append("VendorIE: " + ", ".join(vendor_ies[:4]))
    if caps:
        evidence_bits.append(f"{len(caps)} capability tokens")
    if locally_admin:
        evidence_bits.append("randomized/local MAC")

    return {
        "RegistryVendor": reg["RegistryVendor"],
        "RegistryType": reg["RegistryType"],
        "RegistryPrefix": reg["RegistryPrefix"],
        "HardwareGuess": guess,
        "HardwareConfidence": str(confidence),
        "DirectHardwareHints": "; ".join(direct[:4]) or NO_DATA,
        "VendorIEs": ", ".join(vendor_ies[:6]) or NO_DATA,
        "CapabilityFingerprint": fingerprint,
        "IdentityEvidence": " | ".join(evidence_bits) or NO_DATA,
    }


def _top_values(evidence: Counter, prefix: str) -> List[str]:
    values = []
    for token, _count in evidence.most_common():
        if token.startswith(prefix):
            values.append(token[len(prefix):])
    return values


def _fingerprint(caps: Iterable[str]) -> str:
    joined = "|".join(sorted(caps))
    if not joined:
        return NO_DATA
    return "rfdna-" + hashlib.sha1(joined.encode("utf-8", errors="ignore")).hexdigest()[:12]


def _hardware_guess(reg_vendor: str, direct: List[str], vendor_ies: List[str]) -> str:
    direct_map = {k: v for k, v in (item.split("=", 1) for item in direct if "=" in item)}
    model = direct_map.get("wps.model_name") or direct_map.get("wps.model_number")
    manufacturer = direct_map.get("wps.manufacturer")
    device_name = direct_map.get("wps.device_name")
    if manufacturer and model:
        return f"{manufacturer} {model}"
    if device_name and manufacturer:
        return f"{manufacturer} {device_name}"
    if model:
        return model
    if manufacturer:
        return manufacturer
    if reg_vendor != NO_DATA:
        return reg_vendor
    return NO_DATA


def _confidence(
    role: str,
    locally_admin: bool,
    reg_vendor: str,
    direct: List[str],
    vendor_ies: List[str],
    caps: List[str],
) -> int:
    score = 0
    if reg_vendor != NO_DATA:
        score += 55 if role == "AP" and not locally_admin else 30
    if direct:
        score += 35
    if vendor_ies:
        score += 10
    if caps:
        score += min(12, len(caps) * 2)
    if locally_admin:
        score -= 20
    return max(0, min(95, score))
