"""
WARDRIVE Intelligence Assistant (WIA) — offline analysis interpretation engine.

Architecture
────────────
  WIAEngine
    └─ BaseAssistantProvider  (ABC)
        ├─ RuleBasedProvider  (default, fully offline, no deps)
        └─ LocalLLMProvider   (stub — hook for future llama.cpp / ollama)

The engine:
  1. Reads wardrive_master.csv produced by core/analyze.py.
  2. Builds typed AccessPointEvidence objects.
  3. Passes them through the active provider.
  4. Returns a list of AssistantCard objects ready for UI rendering.

No GUI imports. No network calls in default mode.
Thread-safe: each call is stateless. All mutable state lives in parameters.

Persona
───────
Seasoned cyberpunk operator straight out of a 90s hacker movie.
Duke Nukem energy meets Neo's operator. Technically precise, occasionally
sarcastic, never misleading, and absolutely never offensive or exploitative.
"""
from __future__ import annotations

import csv
import gc
import io
import math
import random
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Tuple


# ─────────────────────────────────────────────────────────────────────────────
# Enums
# ─────────────────────────────────────────────────────────────────────────────

class ConfidenceTier(str, Enum):
    HIGH       = "HIGH CONFIDENCE"
    MODERATE   = "MODERATE CONFIDENCE"
    LOW        = "LOW CONFIDENCE"
    SPECULATIVE = "SPECULATIVE"


class CardSeverity(str, Enum):
    """Visual severity for UI rendering."""
    BOOT    = "BOOT"     # system message, neutral cyan
    INFO    = "INFO"     # informational, grey-blue
    NOTE    = "NOTE"     # observation, teal
    INSIGHT = "INSIGHT"  # positive / interesting, green
    WARN    = "WARN"     # worth attention, amber
    ANOMALY = "ANOMALY"  # something unusual detected, orange
    SCORE   = "SCORE"    # quality score card


class WIAEvent(str, Enum):
    """External events the engine can react to."""
    LOGS_ADDED       = "logs_added"
    PCAPS_ADDED      = "pcaps_added"
    ANALYSIS_START   = "analysis_start"
    ANALYSIS_DONE    = "analysis_done"
    PROJECT_SELECTED = "project_selected"
    INGEST_DONE      = "ingest_done"


# ─────────────────────────────────────────────────────────────────────────────
# Data objects
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AccessPointEvidence:
    mac: str
    ssid: str
    auth: str
    channel: str
    best_rssi: Optional[int]
    avg_rssi: Optional[float]
    sightings: int
    used_for_centroid: int
    confidence_radius_m: Optional[float]
    stability: int
    location_quality: str
    risk_score: int
    seen_in_pcap: bool
    handshake_seen: bool
    eapol_frames: int
    active_days: int
    multi_file: bool
    multi_day: bool
    vendor: str
    first_seen: str
    last_seen: str


@dataclass
class AssistantCard:
    """
    One atomic observation produced by the assistant.
    All sections are plain text — HTML rendering happens in the UI layer.
    """
    title: str
    fact: str
    severity: CardSeverity = CardSeverity.INFO
    confidence: ConfidenceTier = ConfidenceTier.MODERATE
    interpretation: str = ""
    educational_note: str = ""
    mascot_flavor: str = ""
    recommendation: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%H:%M:%S"))


@dataclass
class CaptureQuality:
    score: int          # 0–100
    grade: str          # A / B / C / D / F
    summary: str
    breakdown: List[Tuple[str, int, int]]   # [(label, earned, max), ...]


# ─────────────────────────────────────────────────────────────────────────────
# Educational content library
# ─────────────────────────────────────────────────────────────────────────────

_EDUCATION: Dict[str, str] = {
    "rssi": (
        "RSSI (Received Signal Strength Indicator) is measured in dBm — a negative number. "
        "Closer to zero = stronger signal. -30 dBm is excellent; -90 dBm is barely detectable. "
        "Stronger signals during capture improve centroid accuracy because the device was physically nearby."
    ),
    "centroid": (
        "A centroid is the calculated center-point of all GPS positions where this device was observed. "
        "More observations, especially from different physical angles, shrink the confidence radius and "
        "increase certainty about where the device actually is."
    ),
    "confidence_radius": (
        "The confidence radius (in metres) is the root-mean-squared distance between each GPS sighting "
        "and the centroid. Smaller = more tightly clustered observations = more trustworthy location. "
        "Sparse data, GPS drift, and signal multipath all increase this radius."
    ),
    "randomized_mac": (
        "Modern devices (phones, laptops) randomize their MAC address when probing for networks to prevent "
        "passive tracking. A locally administered MAC has bit 1 of the first byte set. These entries "
        "appear in captures but cannot be reliably attributed to a single physical device across sessions."
    ),
    "bssid": (
        "A BSSID (Basic Service Set Identifier) is a 48-bit MAC address that uniquely identifies one "
        "radio interface of an access point. An AP with multiple radios (2.4 GHz + 5 GHz) has multiple BSSIDs. "
        "The first three bytes identify the hardware vendor (OUI)."
    ),
    "ssid": (
        "An SSID (Service Set Identifier) is the human-readable network name broadcast in beacon frames. "
        "A hidden SSID means the AP transmits blank or zero-length SSID in beacons, but it can still be "
        "captured from probe responses or association frames."
    ),
    "eapol": (
        "EAPOL (Extensible Authentication Protocol over LAN) frames are exchanged during the WPA/WPA2 "
        "4-way handshake — the authentication ceremony between a client and an AP. Capturing a complete "
        "handshake means offline passphrase testing becomes theoretically possible. "
        "WPA3-SAE uses a different (non-EAPOL) handshake that resists this technique."
    ),
    "overlap": (
        "Overlap is the percentage of BSSIDs seen in PCAP captures that also appear in GPS wardrive logs. "
        "High overlap means radio evidence and location evidence are telling the same story. "
        "Low overlap usually means you drove a different route than you sniffed, or one data source is sparse."
    ),
    "channel": (
        "802.11 operates on numbered radio channels. 2.4 GHz channels 1, 6, and 11 don't overlap "
        "(in the US). 5 GHz has many more non-overlapping channels. Channels 36–165 are 5 GHz. "
        "High channel diversity in a capture means the radio was actively scanning, not parked on one band."
    ),
    "stability_score": (
        "The stability score (0–100) combines centroid radius tightness with observation count. "
        "A score of 80+ means the estimated location is likely within 25–30 metres. "
        "Scores below 40 should be treated as approximate — useful for area-level attribution only."
    ),
    "wep": (
        "WEP (Wired Equivalent Privacy) is a cryptographic protocol from 1999. It was formally deprecated "
        "by the IEEE in 2004 and is trivially breakable with modern tools. Any network still using WEP "
        "has a serious configuration problem. No modern device should be using it."
    ),
    "probe": (
        "Probe requests are sent by client devices when actively searching for known networks. "
        "They may reveal SSIDs the client has connected to before. Modern OS implementations often "
        "send wildcard probes (no SSID) and randomize their MAC to limit exposure."
    ),
    "gps_drift": (
        "GPS accuracy degrades near buildings (urban canyon), under dense tree cover, and at low "
        "satellite fix counts. Reported accuracy in meters (AccuracyMeters column) reflects the "
        "receiver's self-estimated uncertainty. WIA uses this to weight each sighting — "
        "high-accuracy fixes contribute more to the centroid than low-accuracy ones."
    ),
}


# ─────────────────────────────────────────────────────────────────────────────
# Persona flavor pools
# ─────────────────────────────────────────────────────────────────────────────

_FLAVOR_DONE: List[str] = [
    "Boom. Data's talking. Listen close.",
    "The air doesn't lie, operator. The packets never do.",
    "Clean run. Your evidence vault just got heavier.",
    "Another dataset, another chapter. This one's got style.",
    "Not bad. Not bad at all. Now don't get cocky.",
    "Evidence stacked. Story told. Welcome to the future.",
    "I've seen worse datasets. I've also seen better. This one's... respectable.",
    "That's a wrap. Go read your reports like the professional you almost are.",
]

_FLAVOR_HIGH_OVERLAP: List[str] = [
    "GPS and radio evidence shaking hands. I love it when a plan comes together.",
    "High overlap. Your wardrive and your sniffer were best friends today.",
    "PCAP confirms GPS confirms PCAP. Circular validation, beautiful.",
]

_FLAVOR_LOW_OVERLAP: List[str] = [
    "GPS says one thing, packets say another. You drove a different route than you sniffed. Classic.",
    "Low overlap. Either your paths diverged or one data source is half-asleep.",
    "That gap between log MACs and PCAP BSSIDs? That's opportunity. Or it's just Tuesday.",
]

_FLAVOR_RANDOMIZED: List[str] = [
    "Randomized MACs. The device thinks it's invisible. It's not, but points for trying.",
    "Locally administered addresses spotted. Privacy-conscious hardware — or just a modern phone.",
    "These MACs aren't real permanent identifiers. Treat them as ghosts.",
]

_FLAVOR_SPARSE: List[str] = [
    "Only one sighting? The universe gave you one frame. Use it wisely.",
    "Sparse data is honest data. Don't extrapolate what you don't know.",
    "Single-sighting APs are breadcrumbs, not a meal.",
]

_FLAVOR_WEP: List[str] = [
    "WEP in 2026. That's like a deadbolt made of cheese. Educational observation only.",
    "WEP spotted. Someone didn't get the memo. Several memos. All the memos.",
    "WEP: encryption theatre. Worth noting for documentation purposes.",
]

_FLAVOR_EAPOL: List[str] = [
    "EAPOL frames? The handshake is in the evidence. Note it, don't exploit it.",
    "4-way handshake captured. This is evidence of authentication activity — document accordingly.",
    "Handshake material in the vault. This has forensic value.",
]

_FLAVOR_QUALITY_HIGH: List[str] = [
    "This capture is chef's kiss. You actually know how to collect evidence.",
    "Top-tier dataset. Whoever drove this route knew what they were doing.",
    "High quality. Your future self will thank you. Your present self: well done.",
]

_FLAVOR_QUALITY_MED: List[str] = [
    "Solid capture. A few more passes and this becomes excellent.",
    "Good data. Not perfect. Perfect doesn't exist. This is close enough.",
    "Respectable. I've worked with worse. Actually I prefer this.",
]

_FLAVOR_QUALITY_LOW: List[str] = [
    "This data has potential. It just needs more... everything.",
    "Sparse capture. Do another pass — the evidence will thank you.",
    "Low quality score doesn't mean bad data, it means thin data. Rescan.",
]


def _pick(pool: List[str], rng: Optional[random.Random] = None) -> str:
    r = rng or random
    return r.choice(pool) if pool else ""


# ─────────────────────────────────────────────────────────────────────────────
# CSV reader → AccessPointEvidence list
# ─────────────────────────────────────────────────────────────────────────────

_NO_DATA_VALS = {"", "N/A", "—", "n/a", "none", "null"}


def _safe_int(v: str, default: Optional[int] = None) -> Optional[int]:
    try:
        return int(float(v))
    except (ValueError, TypeError):
        return default


def _safe_float(v: str, default: Optional[float] = None) -> Optional[float]:
    try:
        f = float(v)
        return f if math.isfinite(f) else default
    except (ValueError, TypeError):
        return default


def _safe_bool(v: str) -> bool:
    return str(v).strip().lower() in ("yes", "true", "1")


def _is_randomized_mac(mac: str) -> bool:
    """Detect locally administered MAC (bit 1 of first byte set)."""
    try:
        first_byte = int(mac.replace(":", "").replace("-", "")[0:2], 16)
        return bool(first_byte & 0x02)
    except (ValueError, IndexError):
        return False


def load_evidence_from_csv(csv_path: str) -> List[AccessPointEvidence]:
    """Read wardrive_master.csv and return a list of AccessPointEvidence objects."""
    results: List[AccessPointEvidence] = []
    try:
        # Read entire file to string first — closes the file descriptor
        # before any CSV iteration begins.  Python 3.14's incremental GC
        # fires inside csv.__next__ when the reader is live in a background
        # thread and causes a fatal access violation.  Parsing from an
        # in-memory StringIO with GC disabled for the duration eliminates
        # both hazards.
        with open(csv_path, encoding="utf-8", errors="replace") as f:
            raw_text = f.read()
        _gc_was_on = gc.isenabled()
        gc.disable()
        try:
            raw_rows = list(csv.DictReader(io.StringIO(raw_text)))
        finally:
            if _gc_was_on:
                gc.enable()
        for row in raw_rows:
            mac = row.get("MAC", "").strip()
            if not mac:
                continue

            ssid = row.get("TopSSID", "").strip()
            auth = row.get("AuthMode", "").strip()
            if auth in _NO_DATA_VALS:
                auth = ""

            conf_raw = row.get("ConfidenceRadiusM", "")
            conf_m = None if conf_raw in _NO_DATA_VALS else _safe_float(conf_raw)

            best_rssi = _safe_int(row.get("BestRSSI", ""))
            avg_rssi = _safe_float(row.get("AvgRSSI", ""))

            results.append(AccessPointEvidence(
                mac=mac,
                ssid=ssid if ssid not in _NO_DATA_VALS else "",
                auth=auth,
                channel=row.get("Channel", "").strip(),
                best_rssi=best_rssi,
                avg_rssi=avg_rssi,
                sightings=_safe_int(row.get("Sightings", ""), 0) or 0,
                used_for_centroid=_safe_int(row.get("UsedForCentroid", ""), 0) or 0,
                confidence_radius_m=conf_m,
                stability=_safe_int(row.get("Stability", ""), 0) or 0,
                location_quality=row.get("LocationQuality", "").strip(),
                risk_score=_safe_int(row.get("RiskScore", ""), 0) or 0,
                seen_in_pcap=_safe_bool(row.get("SeenInPCAP", "")),
                handshake_seen=_safe_bool(row.get("HandshakeSeen", "")),
                eapol_frames=_safe_int(row.get("EAPOLFrames", ""), 0) or 0,
                active_days=_safe_int(row.get("ActiveDays", ""), 0) or 0,
                multi_file=_safe_bool(row.get("RepeatedAcrossFiles", "")),
                multi_day=_safe_bool(row.get("MultiDaySeen", "")),
                vendor=row.get("Vendor", row.get("OUI", "")).strip(),
                first_seen=row.get("FirstSeen", "").strip(),
                last_seen=row.get("LastSeen", "").strip(),
            ))
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Provider interface
# ─────────────────────────────────────────────────────────────────────────────

class BaseAssistantProvider(ABC):
    """
    Contract for all assistant providers.
    Implementations must be stateless across calls — each call to interpret()
    receives the full evidence list and stats and returns fresh cards.
    """

    @abstractmethod
    def interpret(
        self,
        evidence: List[AccessPointEvidence],
        stats: Dict,
    ) -> List[AssistantCard]:
        """Generate cards from evidence + run-level stats."""
        ...

    @abstractmethod
    def on_event(
        self,
        event: WIAEvent,
        context: Dict,
    ) -> Optional[AssistantCard]:
        """React to a workflow event. Returns one card or None."""
        ...

    @abstractmethod
    def quality_score(
        self,
        evidence: List[AccessPointEvidence],
        stats: Dict,
    ) -> CaptureQuality:
        ...


# ─────────────────────────────────────────────────────────────────────────────
# Rule-based provider (fully offline, zero dependencies)
# ─────────────────────────────────────────────────────────────────────────────

class RuleBasedProvider(BaseAssistantProvider):
    """
    Deterministic rule engine.

    Each _analyze_* method targets one observation category and returns 0-N cards.
    Rules are explicit, auditable, and never claim more certainty than the data supports.
    """

    # Thresholds (tunable)
    OVERLAP_HIGH_PCT    = 60.0
    OVERLAP_LOW_PCT     = 20.0
    SPARSE_SIGHTINGS    = 3
    MOBILE_RADIUS_M     = 500.0
    LARGE_RADIUS_M      = 200.0
    STRONG_RSSI         = -55
    DENSE_CLUSTER_N     = 20
    CHANNEL_CONGESTION_THRESHOLD = 0.5   # fraction of APs on same channel = congested
    RANDOMIZED_FRACTION_WARN    = 0.15   # 15%+ randomized MACs = notable

    def __init__(self, seed: Optional[int] = None) -> None:
        self._rng = random.Random(seed)

    # ── Public interface ──────────────────────────────────────────────────────

    def interpret(
        self,
        evidence: List[AccessPointEvidence],
        stats: Dict,
    ) -> List[AssistantCard]:
        if not evidence:
            return [AssistantCard(
                title="No Evidence Loaded",
                fact="The CSV contained no parseable AP records.",
                severity=CardSeverity.WARN,
                confidence=ConfidenceTier.HIGH,
                interpretation="Either the analysis produced no results, or the CSV format was unexpected.",
                educational_note=_EDUCATION["centroid"],
                mascot_flavor="Nothing here. That's either a very clean environment or a very short drive.",
            )]

        cards: List[AssistantCard] = []
        cards.extend(self._analyze_overlap(evidence, stats))
        cards.extend(self._analyze_confidence(evidence))
        cards.extend(self._analyze_mobility(evidence))
        cards.extend(self._analyze_randomized_macs(evidence))
        cards.extend(self._analyze_sparse_data(evidence))
        cards.extend(self._analyze_signal_profile(evidence))
        cards.extend(self._analyze_channel_congestion(evidence))
        cards.extend(self._analyze_vendor_density(evidence))
        cards.extend(self._analyze_suspicious_names(evidence))
        cards.extend(self._analyze_eapol(evidence))
        cards.extend(self._analyze_wep(evidence))
        cards.extend(self._analyze_pcap_only(evidence))
        return cards

    def on_event(self, event: WIAEvent, context: Dict) -> Optional[AssistantCard]:
        if event == WIAEvent.LOGS_ADDED:
            n = context.get("count", 0)
            return AssistantCard(
                title="Wardrive Logs Loaded",
                fact=f"{n} log file(s) queued for analysis.",
                severity=CardSeverity.INFO,
                confidence=ConfidenceTier.HIGH,
                interpretation="GPS position data is now available. Add PCAPs for radio evidence correlation.",
                educational_note=_EDUCATION["rssi"],
                mascot_flavor="GPS evidence locked. I can feel the coordinates from here.",
            )
        if event == WIAEvent.PCAPS_ADDED:
            n = context.get("count", 0)
            return AssistantCard(
                title="PCAP Files Loaded",
                fact=f"{n} PCAP capture file(s) queued.",
                severity=CardSeverity.INFO,
                confidence=ConfidenceTier.HIGH,
                interpretation="Radio frame evidence is available. Combine with wardrive logs for full correlation.",
                educational_note=_EDUCATION["bssid"],
                mascot_flavor="Packets in the vault. The air was talking. We recorded it.",
            )
        if event == WIAEvent.ANALYSIS_START:
            logs = context.get("logs", 0)
            pcaps = context.get("pcaps", 0)
            return AssistantCard(
                title="Analysis Initializing",
                fact=f"Engine starting with {logs} log(s) and {pcaps} PCAP(s).",
                severity=CardSeverity.BOOT,
                confidence=ConfidenceTier.HIGH,
                interpretation="Centroid computation, PCAP correlation, and report generation are queued.",
                mascot_flavor="Boot sequence live. Next stop: evidence.",
            )
        if event == WIAEvent.INGEST_DONE:
            imported = context.get("imported", 0)
            dupes = context.get("duplicates", 0)
            return AssistantCard(
                title="Evidence Ingested",
                fact=f"{imported} file(s) attached to project vault. {dupes} duplicate(s) skipped.",
                severity=CardSeverity.INFO,
                confidence=ConfidenceTier.HIGH,
                interpretation="Evidence is now attached. Run analysis to generate reports.",
                mascot_flavor="Vault updated. The evidence doesn't lie — it just waits.",
            )
        if event == WIAEvent.PROJECT_SELECTED:
            return AssistantCard(
                title="Project Vault Loaded",
                fact=f"Project: {context.get('path', 'unknown')}",
                severity=CardSeverity.BOOT,
                confidence=ConfidenceTier.HIGH,
                interpretation="All prior evidence and runs for this project are accessible.",
                mascot_flavor="Project locked. I know where we keep the bodies. The digital ones.",
            )
        return None

    def quality_score(
        self,
        evidence: List[AccessPointEvidence],
        stats: Dict,
    ) -> CaptureQuality:
        breakdown: List[Tuple[str, int, int]] = []

        # 1. Overlap (40 pts): how much GPS + PCAP evidence agrees
        overlap_pct = float(stats.get("overlap_pct", 0) or 0)
        overlap_earned = min(40, int(overlap_pct * 0.4))
        breakdown.append(("GPS ↔ PCAP overlap", overlap_earned, 40))

        # 2. GPS fix quality (25 pts)
        total = len(evidence)
        high_q = sum(1 for e in evidence if e.location_quality == "High")
        med_q  = sum(1 for e in evidence if e.location_quality == "Medium")
        gps_earned = 0
        if total > 0:
            gps_frac = (high_q + med_q * 0.5) / total
            gps_earned = min(25, int(gps_frac * 25))
        breakdown.append(("High/Med GPS quality", gps_earned, 25))

        # 3. Sample density (20 pts): avg sightings per AP
        avg_sightings = float(stats.get("avg_sightings", 0) or 0)
        density_earned = min(20, int(min(avg_sightings / 5.0, 1.0) * 20))
        breakdown.append(("Avg sightings per AP", density_earned, 20))

        # 4. Channel diversity (15 pts)
        channels = [e.channel for e in evidence if e.channel and e.channel not in _NO_DATA_VALS]
        unique_ch = len(set(channels))
        ch_earned = min(15, unique_ch * 2)
        breakdown.append(("Channel diversity", ch_earned, 15))

        score = sum(e for _, e, _ in breakdown)
        score = max(0, min(100, score))

        if score >= 80:
            grade = "A"
            summary = "Excellent capture. Strong overlap, good GPS fix quality, and solid sample density."
            flavor = _pick(_FLAVOR_QUALITY_HIGH, self._rng)
        elif score >= 60:
            grade = "B"
            summary = "Good capture. A few more passes or better GPS conditions would push this to excellent."
            flavor = _pick(_FLAVOR_QUALITY_MED, self._rng)
        elif score >= 40:
            grade = "C"
            summary = "Fair capture. Evidence is present but thin. Consider rescanning with both logs and PCAPs active."
            flavor = _pick(_FLAVOR_QUALITY_LOW, self._rng)
        elif score >= 20:
            grade = "D"
            summary = "Sparse capture. Centroids will be uncertain. More evidence from multiple directions is needed."
            flavor = _pick(_FLAVOR_QUALITY_LOW, self._rng)
        else:
            grade = "F"
            summary = "Minimal evidence. This dataset cannot support confident location claims."
            flavor = "This is the start of a dataset, not the end."

        breakdown.append(("FLAVOR", 0, 0))  # placeholder row for rendering
        _ = flavor  # consumed below

        return CaptureQuality(
            score=score,
            grade=grade,
            summary=f"{summary} {flavor}",
            breakdown=breakdown[:-1],  # remove placeholder
        )

    # ── Analysis methods ─────────────────────────────────────────────────────

    def _analyze_overlap(
        self, evidence: List[AccessPointEvidence], stats: Dict
    ) -> List[AssistantCard]:
        overlap_pct = float(stats.get("overlap_pct", 0) or 0)
        pcap_unique = int(stats.get("pcap_unique", 0) or 0)
        log_unique  = int(stats.get("log_unique", 0) or 0)
        overlap_n   = int(stats.get("overlap_n", 0) or 0)

        if pcap_unique == 0 and log_unique == 0:
            return []

        if pcap_unique == 0:
            return [AssistantCard(
                title="No PCAP Evidence",
                fact=f"GPS logs found {log_unique} unique MACs. No PCAP captures were analysed.",
                severity=CardSeverity.WARN,
                confidence=ConfidenceTier.HIGH,
                interpretation="Location data is available but radio frame evidence is absent. "
                               "PCAP correlation is not possible without capture files.",
                educational_note=_EDUCATION["overlap"],
                recommendation="Capture PCAPs during your next wardrive and attach them to this project.",
                mascot_flavor="GPS without packets is half the story. Come back with a radio.",
            )]

        if log_unique == 0:
            return [AssistantCard(
                title="No GPS Log Evidence",
                fact=f"PCAP captures found {pcap_unique} unique BSSIDs. No wardrive GPS logs were analysed.",
                severity=CardSeverity.WARN,
                confidence=ConfidenceTier.HIGH,
                interpretation="Radio frame evidence is present but cannot be placed on a map. "
                               "Centroid computation requires GPS sightings.",
                educational_note=_EDUCATION["centroid"],
                recommendation="Attach wardrive GPS logs (WiGLE-format CSV) to enable location correlation.",
                mascot_flavor="Radio without GPS is noise without a map. One out of two. Not great.",
            )]

        cards: List[AssistantCard] = []

        if overlap_pct >= self.OVERLAP_HIGH_PCT:
            cards.append(AssistantCard(
                title="Strong Evidence Correlation",
                fact=f"{overlap_n} of {pcap_unique} PCAP BSSIDs ({overlap_pct:.0f}%) matched GPS wardrive logs.",
                severity=CardSeverity.INSIGHT,
                confidence=ConfidenceTier.HIGH,
                interpretation=(
                    "High overlap indicates your capture path closely matched your wardrive route. "
                    "Location claims for these APs are supported by both GPS and radio evidence — "
                    "this is the strongest possible evidence combination."
                ),
                educational_note=_EDUCATION["overlap"],
                mascot_flavor=_pick(_FLAVOR_HIGH_OVERLAP, self._rng),
            ))
        elif overlap_pct < self.OVERLAP_LOW_PCT and pcap_unique > 5:
            gap = log_unique - overlap_n
            cards.append(AssistantCard(
                title="Low GPS / PCAP Overlap",
                fact=(
                    f"Only {overlap_n} of {pcap_unique} PCAP BSSIDs ({overlap_pct:.0f}%) "
                    f"matched GPS logs. {gap} GPS MACs have no PCAP counterpart."
                ),
                severity=CardSeverity.WARN,
                confidence=ConfidenceTier.MODERATE,
                interpretation=(
                    "Low overlap typically means the capture path diverged from the wardrive route, "
                    "or one data source covers a different time period. "
                    "PCAP-only BSSIDs have no confirmed location. GPS-only MACs have no radio fingerprint."
                ),
                educational_note=_EDUCATION["overlap"],
                recommendation=(
                    "Synchronise your wardrive log capture with your PCAP capture — "
                    "both should run simultaneously on the same physical route."
                ),
                mascot_flavor=_pick(_FLAVOR_LOW_OVERLAP, self._rng),
            ))
        else:
            # Moderate overlap — just an informational note
            cards.append(AssistantCard(
                title="Evidence Correlation",
                fact=f"{overlap_n} of {pcap_unique} PCAP BSSIDs ({overlap_pct:.0f}%) confirmed in GPS logs.",
                severity=CardSeverity.NOTE,
                confidence=ConfidenceTier.MODERATE,
                interpretation=(
                    "Partial overlap. Location evidence supports a subset of radio observations. "
                    "APs seen in both sources have stronger location confidence."
                ),
                educational_note=_EDUCATION["overlap"],
                mascot_flavor="Partial match. The truth is in the middle, as usual.",
            ))
        return cards

    def _analyze_confidence(self, evidence: List[AccessPointEvidence]) -> List[AssistantCard]:
        has_loc = [e for e in evidence if e.confidence_radius_m is not None]
        if not has_loc:
            return []

        high_conf = [e for e in has_loc if e.confidence_radius_m is not None and e.confidence_radius_m <= 50 and e.sightings >= 4]
        uncertain = [e for e in has_loc if e.confidence_radius_m is not None and e.confidence_radius_m > self.LARGE_RADIUS_M]
        cards: List[AssistantCard] = []

        if high_conf:
            top = sorted(high_conf, key=lambda e: e.confidence_radius_m or 999)[:3]
            examples = ", ".join(
                f"{e.ssid or e.mac} ({e.confidence_radius_m:.0f} m)" for e in top
            )
            cards.append(AssistantCard(
                title=f"High-Confidence Locations ({len(high_conf)} APs)",
                fact=(
                    f"{len(high_conf)} access point(s) have a confidence radius ≤ 50 m "
                    f"with ≥ 4 GPS fixes. Examples: {examples}."
                ),
                severity=CardSeverity.INSIGHT,
                confidence=ConfidenceTier.HIGH,
                interpretation=(
                    "These APs have tightly clustered GPS sightings. "
                    "The centroid estimate is likely within 25–50 metres of the actual device. "
                    "This is suitable for sector-level or building-level attribution."
                ),
                educational_note=_EDUCATION["confidence_radius"],
                mascot_flavor="Tight radius. You collected clean data. I'm almost impressed.",
            ))

        if uncertain:
            worst = sorted(uncertain, key=lambda e: -(e.confidence_radius_m or 0))[:3]
            examples = ", ".join(
                f"{e.ssid or e.mac} ({e.confidence_radius_m:.0f} m)" for e in worst
            )
            cards.append(AssistantCard(
                title=f"Uncertain Location Estimates ({len(uncertain)} APs)",
                fact=(
                    f"{len(uncertain)} AP(s) have confidence radius > {self.LARGE_RADIUS_M:.0f} m. "
                    f"Highest uncertainty: {examples}."
                ),
                severity=CardSeverity.WARN,
                confidence=ConfidenceTier.MODERATE,
                interpretation=(
                    "Large confidence radius indicates sparse sightings, GPS drift, "
                    "or signal multipath. Location estimates for these APs should be "
                    "treated as area-level rather than point-level."
                ),
                educational_note=_EDUCATION["gps_drift"],
                recommendation=(
                    "Rescan the area from different physical positions to triangulate a tighter centroid."
                ),
                mascot_flavor="Wide radius means wide uncertainty. The data is honest about what it doesn't know.",
            ))

        return cards

    def _analyze_mobility(self, evidence: List[AccessPointEvidence]) -> List[AssistantCard]:
        """Detect APs with extremely high confidence radius — possible mobile transmitters."""
        mobile_candidates = [
            e for e in evidence
            if e.confidence_radius_m is not None
            and e.confidence_radius_m > self.MOBILE_RADIUS_M
            and e.sightings >= 3
        ]
        if not mobile_candidates:
            return []

        top = sorted(mobile_candidates, key=lambda e: -(e.confidence_radius_m or 0))[:5]
        lines = [f"  {e.ssid or e.mac}: {e.confidence_radius_m:.0f} m radius, {e.sightings} sightings" for e in top]

        return [AssistantCard(
            title=f"Possible Mobile Transmitters ({len(mobile_candidates)} AP(s))",
            fact=(
                f"{len(mobile_candidates)} AP(s) show confidence radii exceeding {self.MOBILE_RADIUS_M:.0f} m "
                f"across ≥ 3 sightings:\n" + "\n".join(lines)
            ),
            severity=CardSeverity.ANOMALY,
            confidence=ConfidenceTier.SPECULATIVE,
            interpretation=(
                "SPECULATIVE: Extremely high centroid spread with multiple sightings may indicate "
                "a mobile transmitter (vehicle hotspot, phone tethering, mobile AP). "
                "It could also be GPS drift or a high-power AP visible over a very large area. "
                "This is a hypothesis, not a conclusion."
            ),
            educational_note=(
                "A stationary AP observed from different directions produces a tight centroid. "
                "A moving transmitter or one visible over a kilometre-wide area produces a spread centroid. "
                "Distinguish between these by examining the sighting timestamps and your own movement path."
            ),
            mascot_flavor=_pick(_FLAVOR_SPARSE, self._rng),
            recommendation="Cross-reference sighting timestamps with your GPS track to determine if spread correlates with your movement.",
        )]

    def _analyze_randomized_macs(self, evidence: List[AccessPointEvidence]) -> List[AssistantCard]:
        randomized = [e for e in evidence if _is_randomized_mac(e.mac)]
        total = len(evidence)
        if not randomized:
            return []

        frac = len(randomized) / total if total else 0
        severity = CardSeverity.NOTE if frac < self.RANDOMIZED_FRACTION_WARN else CardSeverity.WARN

        return [AssistantCard(
            title=f"Randomized MAC Addresses ({len(randomized)} of {total})",
            fact=(
                f"{len(randomized)} entries ({frac:.0%}) appear to use locally administered MAC addresses, "
                f"consistent with MAC randomization."
            ),
            severity=severity,
            confidence=ConfidenceTier.MODERATE,
            interpretation=(
                "Locally administered MACs cannot be reliably attributed to a single device across capture "
                "sessions. Each randomized address should be treated as a unique, transient identifier. "
                "These are likely client devices (phones, laptops) in probe request or soft-AP mode, "
                "not infrastructure access points."
            ),
            educational_note=_EDUCATION["randomized_mac"],
            mascot_flavor=_pick(_FLAVOR_RANDOMIZED, self._rng),
            recommendation=(
                "Do not attempt cross-session correlation on locally administered MACs. "
                "Treat them as probe evidence, not persistent device identity."
            ),
        )]

    def _analyze_sparse_data(self, evidence: List[AccessPointEvidence]) -> List[AssistantCard]:
        single_sight = [e for e in evidence if e.sightings == 1]
        sparse = [e for e in evidence if 1 < e.sightings <= self.SPARSE_SIGHTINGS]
        total = len(evidence)
        if not single_sight and not sparse:
            return []

        cards: List[AssistantCard] = []

        if single_sight:
            pct = len(single_sight) / total * 100 if total else 0
            cards.append(AssistantCard(
                title=f"Single-Sighting APs ({len(single_sight)}, {pct:.0f}%)",
                fact=(
                    f"{len(single_sight)} AP(s) were observed exactly once. "
                    "No centroid computation is possible for these entries."
                ),
                severity=CardSeverity.WARN,
                confidence=ConfidenceTier.LOW,
                interpretation=(
                    "Single-sighting entries place an AP on a map based on one GPS fix. "
                    "There is no triangulation — just one data point. "
                    "These entries are useful as evidence of presence but not for location accuracy."
                ),
                educational_note=_EDUCATION["confidence_radius"],
                mascot_flavor=_pick(_FLAVOR_SPARSE, self._rng),
                recommendation=(
                    "Drive the same area again from a different direction or distance. "
                    "Multiple sightings from varied positions dramatically improve centroid accuracy."
                ),
            ))

        if len(sparse) > 5:
            cards.append(AssistantCard(
                title=f"Low-Sighting APs ({len(sparse)} with 2–{self.SPARSE_SIGHTINGS} sightings)",
                fact=f"{len(sparse)} AP(s) have only 2–{self.SPARSE_SIGHTINGS} GPS sightings.",
                severity=CardSeverity.NOTE,
                confidence=ConfidenceTier.LOW,
                interpretation=(
                    "Low sighting counts limit centroid precision. "
                    "Two or three sightings is better than one, but typically insufficient for "
                    "sub-100 metre location confidence without exceptional GPS accuracy."
                ),
                educational_note=_EDUCATION["stability_score"],
                recommendation="Target 6–10 sightings per AP for meaningful centroid confidence.",
                mascot_flavor="Thin data. Not useless — but thin.",
            ))

        return cards

    def _analyze_signal_profile(self, evidence: List[AccessPointEvidence]) -> List[AssistantCard]:
        strong = [e for e in evidence if e.best_rssi is not None and e.best_rssi >= self.STRONG_RSSI]
        if not strong:
            return []

        very_strong = [e for e in strong if e.best_rssi is not None and e.best_rssi >= -45]
        cards: List[AssistantCard] = []

        if very_strong:
            top = sorted(very_strong, key=lambda e: -(e.best_rssi or -999))[:5]
            lines = [f"  {e.ssid or e.mac}: {e.best_rssi} dBm" for e in top]
            cards.append(AssistantCard(
                title=f"Very Strong Signals Observed ({len(very_strong)} APs)",
                fact=(
                    f"{len(very_strong)} AP(s) were captured at ≥ -45 dBm:\n" + "\n".join(lines)
                ),
                severity=CardSeverity.NOTE,
                confidence=ConfidenceTier.HIGH,
                interpretation=(
                    "Very strong RSSI (-45 dBm or better) indicates the capture device passed "
                    "within approximately 5–15 metres of the transmitter. "
                    "These entries have the most reliable centroid contributions."
                ),
                educational_note=_EDUCATION["rssi"],
                mascot_flavor="Strong signal. You were close. The AP noticed. Not really, but poetically.",
            ))

        return cards

    def _analyze_channel_congestion(self, evidence: List[AccessPointEvidence]) -> List[AssistantCard]:
        channels = [e.channel for e in evidence if e.channel and e.channel not in _NO_DATA_VALS]
        if len(channels) < 5:
            return []

        from collections import Counter
        counts = Counter(channels)
        total = len(channels)
        most_common_ch, most_common_n = counts.most_common(1)[0]
        congestion_frac = most_common_n / total
        unique_channels = len(counts)

        cards: List[AssistantCard] = []

        if congestion_frac >= self.CHANNEL_CONGESTION_THRESHOLD:
            cards.append(AssistantCard(
                title=f"Channel Congestion — Channel {most_common_ch}",
                fact=(
                    f"{most_common_n} of {total} APs ({congestion_frac:.0%}) are on channel {most_common_ch}. "
                    f"Total unique channels observed: {unique_channels}."
                ),
                severity=CardSeverity.NOTE,
                confidence=ConfidenceTier.HIGH,
                interpretation=(
                    f"Heavy concentration on channel {most_common_ch} is common in dense urban areas "
                    "where many APs default to the same channel. "
                    "This can cause co-channel interference and reduced throughput for devices on that channel."
                ),
                educational_note=_EDUCATION["channel"],
                mascot_flavor=f"Channel {most_common_ch} is having a party. Everyone showed up.",
            ))
        elif unique_channels >= 8:
            cards.append(AssistantCard(
                title=f"Good Channel Diversity ({unique_channels} unique channels)",
                fact=f"{unique_channels} different channels observed across {total} APs.",
                severity=CardSeverity.INSIGHT,
                confidence=ConfidenceTier.HIGH,
                interpretation=(
                    "High channel diversity indicates the capture covered multiple frequency bands "
                    "(2.4 GHz and 5 GHz) and a range of AP configurations. "
                    "This is characteristic of a dense or mixed environment."
                ),
                educational_note=_EDUCATION["channel"],
                mascot_flavor="Multiple bands, multiple channels. The spectrum was generous today.",
            ))

        return cards

    def _analyze_vendor_density(self, evidence: List[AccessPointEvidence]) -> List[AssistantCard]:
        from collections import Counter
        vendors = [
            e.vendor for e in evidence
            if e.vendor and e.vendor not in _NO_DATA_VALS and e.vendor.lower() != "unknown"
        ]
        if len(vendors) < 3:
            return []

        counts = Counter(vendors)
        top_vendor, top_n = counts.most_common(1)[0]
        total = len(evidence)
        frac = top_n / total

        if frac < 0.30:
            return []

        return [AssistantCard(
            title=f"Dominant Vendor — {top_vendor}",
            fact=f"{top_n} of {total} APs ({frac:.0%}) are attributed to vendor: {top_vendor}.",
            severity=CardSeverity.NOTE,
            confidence=ConfidenceTier.MODERATE,
            interpretation=(
                f"A high concentration of one vendor ({top_vendor}) can indicate "
                "a corporate or ISP deployment, a building wired by one installer, "
                "or a residential area where one ISP-supplied model dominates."
            ),
            educational_note=_EDUCATION["bssid"],
            mascot_flavor=f"{top_vendor} everywhere. They must have had a sale.",
        )]

    def _analyze_suspicious_names(self, evidence: List[AccessPointEvidence]) -> List[AssistantCard]:
        """Flag default router names and potentially deceptive SSIDs. Educational only."""
        DEFAULT_PATTERNS = [
            r"^linksys\b", r"^netgear\b", r"^dlink\b", r"^xfinitywifi\b",
            r"^default\b", r"^home\b", r"^router\b", r"^wifi\b",
            r"^TP-LINK", r"^ASUS_", r"^DIRECT-",
        ]
        HONEYPOT_PATTERNS = [
            r"free\s*wifi", r"airport.*wifi", r"hotel.*wifi", r"starbucks",
            r"attwifi", r"xfinity", r"optimum\s*wifi",
        ]

        default_flags: List[AccessPointEvidence] = []
        honeypot_flags: List[AccessPointEvidence] = []

        for e in evidence:
            ssid_lower = e.ssid.lower()
            if any(re.match(p, ssid_lower, re.IGNORECASE) for p in DEFAULT_PATTERNS):
                default_flags.append(e)
            elif any(re.search(p, ssid_lower, re.IGNORECASE) for p in HONEYPOT_PATTERNS):
                honeypot_flags.append(e)

        cards: List[AssistantCard] = []

        if default_flags:
            cards.append(AssistantCard(
                title=f"Default/Generic SSIDs ({len(default_flags)} APs)",
                fact=f"{len(default_flags)} AP(s) use factory-default or generic SSIDs.",
                severity=CardSeverity.NOTE,
                confidence=ConfidenceTier.MODERATE,
                interpretation=(
                    "Default SSIDs suggest the device owner did not customise the router name "
                    "during setup. This is common in residential areas. "
                    "It does not imply any security posture — check the AuthMode column."
                ),
                educational_note=_EDUCATION["ssid"],
                mascot_flavor="Someone took the router out of the box and called it done. Relatable.",
            ))

        if honeypot_flags:
            examples = ", ".join(f'"{e.ssid}"' for e in honeypot_flags[:4])
            cards.append(AssistantCard(
                title=f"Public/Captive Portal SSIDs ({len(honeypot_flags)} APs)",
                fact=f"SSIDs suggesting public/captive portals: {examples}.",
                severity=CardSeverity.NOTE,
                confidence=ConfidenceTier.SPECULATIVE,
                interpretation=(
                    "SPECULATIVE: SSIDs that mimic public infrastructure are common in high-footfall areas "
                    "(transit hubs, coffee shops). They are also used for legitimate captive portals. "
                    "This is an observation about naming patterns, not security posture."
                ),
                educational_note=_EDUCATION["ssid"],
                mascot_flavor="Public Wi-Fi SSIDs. Everyone's connected. Whether they should be is a different question.",
            ))

        return cards

    def _analyze_eapol(self, evidence: List[AccessPointEvidence]) -> List[AssistantCard]:
        eapol_aps = [e for e in evidence if e.handshake_seen or e.eapol_frames > 0]
        if not eapol_aps:
            return []

        total_frames = sum(e.eapol_frames for e in eapol_aps)
        top = sorted(eapol_aps, key=lambda e: -e.eapol_frames)[:5]
        lines = [f"  {e.ssid or e.mac}: {e.eapol_frames} EAPOL frame(s)" for e in top]

        return [AssistantCard(
            title=f"EAPOL / Handshake Evidence ({len(eapol_aps)} APs)",
            fact=(
                f"{len(eapol_aps)} AP(s) produced EAPOL frames ({total_frames} total):\n"
                + "\n".join(lines)
            ),
            severity=CardSeverity.ANOMALY,
            confidence=ConfidenceTier.MODERATE,
            interpretation=(
                "EAPOL frames indicate that a client device attempted to authenticate to these APs "
                "during the capture window. This is normal network activity. "
                "The presence of EAPOL evidence has forensic documentation value. "
                "Complete 4-way handshakes are noted in the HandshakeConfidence column."
            ),
            educational_note=_EDUCATION["eapol"],
            mascot_flavor=_pick(_FLAVOR_EAPOL, self._rng),
            recommendation=(
                "Review the HandshakeConfidence column in the CSV. "
                "'CONFIRMED' means a complete 4-way handshake was captured. "
                "Document this evidence according to your operational protocol."
            ),
        )]

    def _analyze_wep(self, evidence: List[AccessPointEvidence]) -> List[AssistantCard]:
        wep_aps = [e for e in evidence if "WEP" in (e.auth or "").upper()]
        if not wep_aps:
            return []

        examples = ", ".join(f'"{e.ssid or e.mac}"' for e in wep_aps[:5])
        return [AssistantCard(
            title=f"Legacy WEP Encryption ({len(wep_aps)} APs)",
            fact=f"{len(wep_aps)} AP(s) broadcast WEP authentication: {examples}.",
            severity=CardSeverity.ANOMALY,
            confidence=ConfidenceTier.HIGH,
            interpretation=(
                "WEP (Wired Equivalent Privacy) was formally deprecated by the IEEE in 2004 and is "
                "known to be cryptographically broken. Its presence in 2026 is a significant "
                "configuration anomaly worth documenting."
            ),
            educational_note=_EDUCATION["wep"],
            mascot_flavor=_pick(_FLAVOR_WEP, self._rng),
            recommendation=(
                "Document the MAC, SSID, and location of WEP networks for your report. "
                "This is evidence of outdated configuration, not an exploitation opportunity."
            ),
        )]

    def _analyze_pcap_only(self, evidence: List[AccessPointEvidence]) -> List[AssistantCard]:
        """Flag APs seen only in PCAP (no GPS fix)."""
        pcap_only = [
            e for e in evidence
            if e.seen_in_pcap and e.used_for_centroid == 0 and e.confidence_radius_m is None
        ]
        if len(pcap_only) < 3:
            return []

        return [AssistantCard(
            title=f"PCAP-Only APs — No Location Fix ({len(pcap_only)})",
            fact=(
                f"{len(pcap_only)} AP(s) were detected in PCAP captures but have no GPS centroid. "
                "They cannot be placed on the map."
            ),
            severity=CardSeverity.NOTE,
            confidence=ConfidenceTier.HIGH,
            interpretation=(
                "These APs were radio-visible during capture but not logged in any wardrive GPS file. "
                "They may have been heard during a passive sniff on a stationary position, "
                "or they exist in a part of the spectrum that GPS logging did not cover."
            ),
            educational_note=_EDUCATION["overlap"],
            recommendation=(
                "If location matters for these APs: drive the area with both GPS logging and "
                "passive capture active simultaneously."
            ),
            mascot_flavor="They showed up in the radio but not on the map. Ghosts. Digital ghosts.",
        )]


# ─────────────────────────────────────────────────────────────────────────────
# LocalLLM stub provider
# ─────────────────────────────────────────────────────────────────────────────

class LocalLLMProvider(BaseAssistantProvider):
    """
    Stub for future local LLM integration (llama.cpp / ollama / LM Studio).

    Replace the body of interpret() with your model call.
    The interface contract is: receive evidence list + stats dict, return AssistantCard list.
    No cloud API calls — all inference must happen on-device.
    """

    def __init__(self, model_path: Optional[str] = None) -> None:
        self._model_path = model_path
        self._fallback = RuleBasedProvider()

    def interpret(
        self, evidence: List[AccessPointEvidence], stats: Dict
    ) -> List[AssistantCard]:
        # Stub: fall back to rule-based until a model is wired in.
        cards = self._fallback.interpret(evidence, stats)
        cards.insert(0, AssistantCard(
            title="Local LLM Provider (Stub)",
            fact="No local model is configured. Falling back to rule-based analysis.",
            severity=CardSeverity.BOOT,
            confidence=ConfidenceTier.HIGH,
            interpretation="Wire a llama.cpp or ollama endpoint into LocalLLMProvider.interpret() to enable model-backed analysis.",
            mascot_flavor="The LLM socket is open. Just needs a model. Drop one in and call me.",
        ))
        return cards

    def on_event(self, event: WIAEvent, context: Dict) -> Optional[AssistantCard]:
        return self._fallback.on_event(event, context)

    def quality_score(
        self, evidence: List[AccessPointEvidence], stats: Dict
    ) -> CaptureQuality:
        return self._fallback.quality_score(evidence, stats)


# ─────────────────────────────────────────────────────────────────────────────
# WIAEngine — public entry point
# ─────────────────────────────────────────────────────────────────────────────

class WIAEngine:
    """
    Orchestrates evidence loading → provider dispatch → card output.

    Usage:
        engine = WIAEngine()
        cards  = engine.analyze_results(results_dict)
        quality = engine.get_quality()   # after analyze_results()

    The engine is not thread-safe for concurrent calls to the same instance.
    Create one instance per analysis run, or call from a single thread.
    """

    def __init__(self, provider: Optional[BaseAssistantProvider] = None) -> None:
        self._provider = provider or RuleBasedProvider()
        self._last_quality: Optional[CaptureQuality] = None
        self._last_evidence: List[AccessPointEvidence] = []

    def analyze_results(self, results: Dict) -> List[AssistantCard]:
        """
        Main entry point after analysis completes.

        results: the dict returned by core.analyze.analyze() — must include 'csv' key
                 pointing to wardrive_master.csv, and optionally 'stats' key.
        """
        csv_path = results.get("csv", "")
        stats    = results.get("stats", {}) or {}

        evidence = load_evidence_from_csv(csv_path) if csv_path else []
        self._last_evidence = evidence

        quality = self._provider.quality_score(evidence, stats)
        self._last_quality = quality

        cards = self._provider.interpret(evidence, stats)

        # Prepend a done card with mascot flavor
        rng = random.Random()
        done_card = AssistantCard(
            title="Analysis Complete",
            fact=(
                f"{len(evidence)} AP records processed. "
                f"Capture quality: {quality.score}/100 (Grade {quality.grade})."
            ),
            severity=CardSeverity.BOOT,
            confidence=ConfidenceTier.HIGH,
            interpretation=quality.summary,
            mascot_flavor=_pick(_FLAVOR_DONE, rng),
        )
        return [done_card] + cards

    def on_event(self, event: WIAEvent, context: Dict) -> Optional[AssistantCard]:
        """React to a workflow event and return an optional card."""
        return self._provider.on_event(event, context)

    def get_quality(self) -> Optional[CaptureQuality]:
        return self._last_quality

    def get_educational_note(self, topic: str) -> str:
        """Return a plain-text educational note for a given topic key."""
        return _EDUCATION.get(topic.lower(), f"No entry found for topic: '{topic}'")

    def list_educational_topics(self) -> List[str]:
        return list(_EDUCATION.keys())

    def explain_ap(self, mac: str) -> List[AssistantCard]:
        """
        Generate a focused explanation card for a specific AP from the last analysis.
        Useful for right-click / context menu 'Explain this AP' actions.
        """
        match = next((e for e in self._last_evidence if e.mac == mac), None)
        if not match:
            return [AssistantCard(
                title=f"AP Not Found: {mac}",
                fact="This MAC was not in the last analysed dataset.",
                severity=CardSeverity.WARN,
                confidence=ConfidenceTier.HIGH,
            )]

        e = match
        loc_str = (
            f"Confidence radius: {e.confidence_radius_m:.0f} m "
            f"({e.location_quality} quality, {e.used_for_centroid} points used)"
            if e.confidence_radius_m is not None
            else "No GPS location fix."
        )
        rssi_str = (
            f"Best RSSI: {e.best_rssi} dBm. Avg: {e.avg_rssi} dBm."
            if e.best_rssi is not None
            else "No RSSI data."
        )
        pcap_str = "Seen in PCAP." if e.seen_in_pcap else "Not in PCAP captures."
        eapol_str = f"EAPOL frames: {e.eapol_frames}." if e.handshake_seen else ""

        fact = (
            f"MAC: {e.mac}\n"
            f"SSID: {e.ssid or '(hidden/unknown)'}\n"
            f"Auth: {e.auth or 'unknown'}\n"
            f"Channel: {e.channel or 'unknown'}\n"
            f"Vendor: {e.vendor or 'unknown'}\n"
            f"Sightings: {e.sightings}  |  Active days: {e.active_days}\n"
            f"{rssi_str}\n"
            f"{loc_str}\n"
            f"Stability score: {e.stability}/100\n"
            f"Risk score: {e.risk_score}\n"
            f"{pcap_str}  {eapol_str}"
        ).strip()

        interp_parts: List[str] = []
        if e.confidence_radius_m is not None and e.confidence_radius_m <= 50:
            interp_parts.append("Location estimate is HIGH CONFIDENCE.")
        elif e.confidence_radius_m is not None and e.confidence_radius_m > self._provider.LARGE_RADIUS_M \
                if hasattr(self._provider, "LARGE_RADIUS_M") else e.confidence_radius_m is not None and e.confidence_radius_m > 200:
            interp_parts.append("Location estimate is UNCERTAIN (wide radius).")

        if _is_randomized_mac(e.mac):
            interp_parts.append("MAC appears locally administered — likely randomized.")

        if e.handshake_seen:
            interp_parts.append("EAPOL evidence present — document per operational protocol.")

        if "WEP" in (e.auth or "").upper():
            interp_parts.append("WEP encryption — severely outdated configuration.")

        if e.sightings == 1:
            interp_parts.append("Single sighting — location is a single GPS point, not a triangulated centroid.")

        education_key = "rssi" if e.best_rssi is not None else "centroid"
        if e.handshake_seen:
            education_key = "eapol"
        elif _is_randomized_mac(e.mac):
            education_key = "randomized_mac"
        elif e.confidence_radius_m is not None and e.confidence_radius_m > 200:
            education_key = "gps_drift"

        return [AssistantCard(
            title=f"AP Detail — {e.ssid or e.mac}",
            fact=fact,
            severity=CardSeverity.INFO,
            confidence=ConfidenceTier.HIGH if e.sightings >= 4 else ConfidenceTier.LOW,
            interpretation=" ".join(interp_parts) if interp_parts else "No anomalies detected.",
            educational_note=_EDUCATION.get(education_key, ""),
            mascot_flavor="Here's what I know. Read it carefully.",
        )]
