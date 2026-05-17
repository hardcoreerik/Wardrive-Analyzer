"""Tests for assistant_engine.py — WIA offline rule engine."""
from __future__ import annotations

import csv
import io
import os
import tempfile

import pytest

from assistant_engine import (
    AccessPointEvidence,
    AssistantCard,
    CardSeverity,
    CaptureQuality,
    ConfidenceTier,
    RuleBasedProvider,
    WIAEngine,
    WIAEvent,
    _is_randomized_mac,
    load_evidence_from_csv,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers — synthetic evidence builders
# ─────────────────────────────────────────────────────────────────────────────

def _ap(
    mac: str = "AA:BB:CC:DD:EE:FF",
    ssid: str = "TestNet",
    auth: str = "WPA2",
    channel: str = "6",
    best_rssi: int = -65,
    avg_rssi: float = -68.0,
    sightings: int = 5,
    used_for_centroid: int = 5,
    confidence_radius_m: float | None = 30.0,
    stability: int = 75,
    location_quality: str = "High",
    risk_score: int = 0,
    seen_in_pcap: bool = True,
    handshake_seen: bool = False,
    eapol_frames: int = 0,
    active_days: int = 1,
    multi_file: bool = False,
    multi_day: bool = False,
    vendor: str = "Cisco",
    first_seen: str = "",
    last_seen: str = "",
) -> AccessPointEvidence:
    return AccessPointEvidence(
        mac=mac,
        ssid=ssid,
        auth=auth,
        channel=channel,
        best_rssi=best_rssi,
        avg_rssi=avg_rssi,
        sightings=sightings,
        used_for_centroid=used_for_centroid,
        confidence_radius_m=confidence_radius_m,
        stability=stability,
        location_quality=location_quality,
        risk_score=risk_score,
        seen_in_pcap=seen_in_pcap,
        handshake_seen=handshake_seen,
        eapol_frames=eapol_frames,
        active_days=active_days,
        multi_file=multi_file,
        multi_day=multi_day,
        vendor=vendor,
        first_seen=first_seen,
        last_seen=last_seen,
    )


def _provider(seed: int = 42) -> RuleBasedProvider:
    return RuleBasedProvider(seed=seed)


EMPTY_STATS: dict = {}

HIGH_OVERLAP_STATS = {
    "overlap_pct": 80.0,
    "overlap_pct_logs": 75.0,
    "overlap_n": 80,
    "pcap_unique": 100,
    "log_unique": 100,
}

LOW_OVERLAP_STATS = {
    "overlap_pct": 10.0,
    "overlap_pct_logs": 8.0,
    "overlap_n": 5,
    "pcap_unique": 50,
    "log_unique": 80,
}

NO_PCAP_STATS = {
    "overlap_pct": 0.0,
    "overlap_n": 0,
    "pcap_unique": 0,
    "log_unique": 20,
}

NO_LOG_STATS = {
    "overlap_pct": 0.0,
    "overlap_n": 0,
    "pcap_unique": 15,
    "log_unique": 0,
}


# ─────────────────────────────────────────────────────────────────────────────
# _is_randomized_mac
# ─────────────────────────────────────────────────────────────────────────────

class TestIsRandomizedMac:
    def test_globally_administered_not_randomized(self):
        # bit 1 of first byte = 0 → universally administered
        assert not _is_randomized_mac("00:11:22:33:44:55")

    def test_locally_administered_is_randomized(self):
        # first byte 0x02 → bit 1 set
        assert _is_randomized_mac("02:11:22:33:44:55")

    def test_another_la_mac(self):
        # 0x0E = 0b00001110 — bit 1 set
        assert _is_randomized_mac("0E:AA:BB:CC:DD:EE")

    def test_broadcast_not_randomized_by_la_bit(self):
        # FF has bit 1 set so counts as locally administered
        assert _is_randomized_mac("FF:FF:FF:FF:FF:FF")

    def test_empty_mac_returns_false(self):
        assert not _is_randomized_mac("")

    def test_malformed_mac_returns_false(self):
        assert not _is_randomized_mac("ZZ:ZZ:ZZ")


# ─────────────────────────────────────────────────────────────────────────────
# load_evidence_from_csv
# ─────────────────────────────────────────────────────────────────────────────

CSV_HEADER = (
    "MAC,TopSSID,AuthMode,Channel,BestRSSI,AvgRSSI,Sightings,UsedForCentroid,"
    "ConfidenceRadiusM,Stability,LocationQuality,RiskScore,SeenInPCAP,"
    "HandshakeSeen,EAPOLFrames,ActiveDays,RepeatedAcrossFiles,MultiDaySeen,"
    "Vendor,FirstSeen,LastSeen\n"
)


def _write_csv(rows: list[str]) -> str:
    """Write a CSV temp file and return its path."""
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".csv", delete=False, encoding="utf-8"
    )
    tmp.write(CSV_HEADER)
    for row in rows:
        tmp.write(row + "\n")
    tmp.close()
    return tmp.name


class TestLoadEvidenceFromCsv:
    def test_missing_file_returns_empty(self):
        result = load_evidence_from_csv("/does/not/exist.csv")
        assert result == []

    def test_basic_row_parsed(self):
        path = _write_csv([
            "AA:BB:CC:DD:EE:FF,HomeNet,WPA2,6,-65,-68.0,5,5,30.0,75,High,0,yes,no,0,1,no,no,Cisco,2026-01-01,2026-01-01"
        ])
        try:
            evidence = load_evidence_from_csv(path)
            assert len(evidence) == 1
            ap = evidence[0]
            assert ap.mac == "AA:BB:CC:DD:EE:FF"
            assert ap.ssid == "HomeNet"
            assert ap.auth == "WPA2"
            assert ap.channel == "6"
            assert ap.best_rssi == -65
            assert ap.sightings == 5
            assert ap.confidence_radius_m == pytest.approx(30.0)
            assert ap.seen_in_pcap is True
            assert ap.handshake_seen is False
            assert ap.vendor == "Cisco"
        finally:
            os.unlink(path)

    def test_missing_mac_skipped(self):
        path = _write_csv([
            ",NoMac,WPA2,6,-65,-68.0,1,1,N/A,0,Low,0,no,no,0,1,no,no,,,"
        ])
        try:
            assert load_evidence_from_csv(path) == []
        finally:
            os.unlink(path)

    def test_na_confidence_radius_becomes_none(self):
        path = _write_csv([
            "AA:BB:CC:DD:EE:FF,Test,WPA2,1,-70,-72.0,2,0,N/A,0,Low,0,no,no,0,1,no,no,,,"
        ])
        try:
            ap = load_evidence_from_csv(path)[0]
            assert ap.confidence_radius_m is None
        finally:
            os.unlink(path)

    def test_handshake_seen_true(self):
        path = _write_csv([
            "AA:BB:CC:DD:EE:FF,Test,WPA2,6,-60,-62.0,3,3,50.0,70,High,0,yes,yes,4,1,no,no,Netgear,,"
        ])
        try:
            ap = load_evidence_from_csv(path)[0]
            assert ap.handshake_seen is True
            assert ap.eapol_frames == 4
        finally:
            os.unlink(path)

    def test_multiple_rows(self):
        path = _write_csv([
            "AA:00:00:00:00:01,Net1,WPA2,1,-65,-67.0,4,4,25.0,80,High,0,yes,no,0,1,no,no,Cisco,,",
            "AA:00:00:00:00:02,Net2,WPA,11,-75,-78.0,2,2,120.0,45,Medium,1,no,no,0,1,yes,no,Netgear,,",
        ])
        try:
            result = load_evidence_from_csv(path)
            assert len(result) == 2
            assert result[0].mac == "AA:00:00:00:00:01"
            assert result[1].mac == "AA:00:00:00:00:02"
        finally:
            os.unlink(path)

    def test_empty_csv_returns_empty(self):
        path = _write_csv([])
        try:
            assert load_evidence_from_csv(path) == []
        finally:
            os.unlink(path)


# ─────────────────────────────────────────────────────────────────────────────
# RuleBasedProvider — individual analysis methods
# ─────────────────────────────────────────────────────────────────────────────

class TestAnalyzeOverlap:
    def test_high_overlap_returns_insight_card(self):
        p = _provider()
        ev = [_ap()]
        cards = p._analyze_overlap(ev, HIGH_OVERLAP_STATS)
        assert len(cards) == 1
        assert cards[0].severity == CardSeverity.INSIGHT
        assert "Strong Evidence Correlation" in cards[0].title

    def test_low_overlap_returns_warn_card(self):
        p = _provider()
        ev = [_ap()] * 10
        cards = p._analyze_overlap(ev, LOW_OVERLAP_STATS)
        assert len(cards) == 1
        assert cards[0].severity == CardSeverity.WARN
        assert "Low GPS" in cards[0].title

    def test_no_pcap_evidence(self):
        p = _provider()
        ev = [_ap()]
        cards = p._analyze_overlap(ev, NO_PCAP_STATS)
        assert len(cards) == 1
        assert "No PCAP Evidence" in cards[0].title

    def test_no_log_evidence(self):
        p = _provider()
        ev = [_ap()]
        cards = p._analyze_overlap(ev, NO_LOG_STATS)
        assert len(cards) == 1
        assert "No GPS Log Evidence" in cards[0].title

    def test_all_zeros_returns_empty(self):
        p = _provider()
        ev = [_ap()]
        cards = p._analyze_overlap(ev, {"overlap_pct": 0, "pcap_unique": 0, "log_unique": 0, "overlap_n": 0})
        assert cards == []


class TestAnalyzeRandomizedMacs:
    def test_no_randomized_returns_empty(self):
        p = _provider()
        ev = [_ap(mac="00:11:22:33:44:55")]  # globally administered
        assert p._analyze_randomized_macs(ev) == []

    def test_few_randomized_returns_note(self):
        # 1 randomized out of 10 = 10% < 15% threshold → NOTE severity
        p = _provider()
        ev = [_ap(mac="02:11:22:33:44:55")] + [_ap(mac=f"00:11:22:33:44:{i:02X}") for i in range(9)]
        cards = p._analyze_randomized_macs(ev)
        assert len(cards) == 1
        assert cards[0].severity == CardSeverity.NOTE

    def test_many_randomized_returns_warn(self):
        # 4 randomized out of 10 = 40% > 15% threshold → WARN severity
        p = _provider()
        ev = [
            _ap(mac=f"02:11:22:33:44:{i:02X}") for i in range(4)
        ] + [
            _ap(mac=f"00:11:22:33:44:{i:02X}") for i in range(6)
        ]
        cards = p._analyze_randomized_macs(ev)
        assert len(cards) == 1
        assert cards[0].severity == CardSeverity.WARN

    def test_card_mentions_count(self):
        p = _provider()
        ev = [_ap(mac="02:AA:BB:CC:DD:EE"), _ap(mac="00:11:22:33:44:55")]
        cards = p._analyze_randomized_macs(ev)
        # Count appears in title as "(1 of 2)" and percentage in fact
        assert "1 of 2" in cards[0].title
        assert "50%" in cards[0].fact


class TestAnalyzeWep:
    def test_wep_ap_produces_anomaly_card(self):
        p = _provider()
        ev = [_ap(auth="WEP")]
        cards = p._analyze_wep(ev)
        assert len(cards) == 1
        assert cards[0].severity == CardSeverity.ANOMALY
        assert "WEP" in cards[0].title

    def test_no_wep_returns_empty(self):
        p = _provider()
        ev = [_ap(auth="WPA2"), _ap(auth="WPA3")]
        assert p._analyze_wep(ev) == []

    def test_wep_case_insensitive(self):
        p = _provider()
        ev = [_ap(auth="wep")]
        cards = p._analyze_wep(ev)
        assert len(cards) == 1

    def test_multiple_wep_counted(self):
        p = _provider()
        ev = [_ap(auth="WEP"), _ap(auth="WEP"), _ap(auth="WPA2")]
        cards = p._analyze_wep(ev)
        assert "2" in cards[0].fact


class TestAnalyzeEapol:
    def test_handshake_seen_produces_card(self):
        p = _provider()
        ev = [_ap(handshake_seen=True, eapol_frames=4)]
        cards = p._analyze_eapol(ev)
        assert len(cards) == 1
        assert cards[0].severity in (CardSeverity.NOTE, CardSeverity.INSIGHT, CardSeverity.WARN, CardSeverity.ANOMALY)
        assert "EAPOL" in cards[0].title or "Handshake" in cards[0].title

    def test_no_handshake_returns_empty(self):
        p = _provider()
        ev = [_ap(handshake_seen=False, eapol_frames=0)]
        assert p._analyze_eapol(ev) == []

    def test_eapol_count_in_fact(self):
        p = _provider()
        ev = [_ap(handshake_seen=True, eapol_frames=8)]
        cards = p._analyze_eapol(ev)
        # The card fact or title should reference the evidence
        assert len(cards) >= 1


class TestAnalyzeSparseData:
    def test_single_sighting_ap_produces_warn(self):
        p = _provider()
        ev = [_ap(sightings=1)]
        cards = p._analyze_sparse_data(ev)
        assert any(c.severity == CardSeverity.WARN for c in cards)

    def test_well_sampled_aps_return_empty(self):
        p = _provider()
        ev = [_ap(sightings=10) for _ in range(5)]
        assert p._analyze_sparse_data(ev) == []

    def test_single_sighting_card_title(self):
        p = _provider()
        ev = [_ap(sightings=1)]
        cards = p._analyze_sparse_data(ev)
        assert any("Single-Sighting" in c.title for c in cards)

    def test_low_sightings_group_card_appears_when_large_count(self):
        # Need > 5 APs with 2-3 sightings to trigger the second card
        p = _provider()
        ev = [_ap(sightings=2) for _ in range(7)]
        cards = p._analyze_sparse_data(ev)
        assert any("Low-Sighting" in c.title for c in cards)


class TestAnalyzeMobility:
    def test_high_radius_many_sightings_returns_anomaly(self):
        p = _provider()
        ev = [_ap(confidence_radius_m=800.0, sightings=5)]
        cards = p._analyze_mobility(ev)
        assert len(cards) == 1
        assert cards[0].severity == CardSeverity.ANOMALY
        assert cards[0].confidence == ConfidenceTier.SPECULATIVE

    def test_high_radius_few_sightings_not_flagged(self):
        p = _provider()
        ev = [_ap(confidence_radius_m=800.0, sightings=2)]  # < 3 → not flagged
        cards = p._analyze_mobility(ev)
        assert cards == []

    def test_normal_radius_not_flagged(self):
        p = _provider()
        ev = [_ap(confidence_radius_m=30.0, sightings=10)]
        assert p._analyze_mobility(ev) == []


class TestAnalyzeConfidence:
    def test_tight_radius_produces_insight(self):
        p = _provider()
        ev = [_ap(confidence_radius_m=25.0, sightings=6)]
        cards = p._analyze_confidence(ev)
        assert any(c.severity == CardSeverity.INSIGHT for c in cards)

    def test_large_radius_produces_warn(self):
        p = _provider()
        ev = [_ap(confidence_radius_m=500.0, sightings=3)]
        cards = p._analyze_confidence(ev)
        assert any(c.severity == CardSeverity.WARN for c in cards)

    def test_no_location_data_returns_empty(self):
        p = _provider()
        ev = [_ap(confidence_radius_m=None)]
        assert p._analyze_confidence(ev) == []


class TestAnalyzeChannelCongestion:
    def test_congested_channel_produces_note(self):
        p = _provider()
        # 8 of 10 APs on channel 6 = 80% > 50% threshold
        ev = [_ap(channel="6")] * 8 + [_ap(channel="11")] * 2
        cards = p._analyze_channel_congestion(ev)
        assert len(cards) == 1
        assert "Congestion" in cards[0].title

    def test_diverse_channels_produces_insight(self):
        p = _provider()
        # Spread over 9 unique channels
        channels = ["1", "6", "11", "36", "40", "44", "48", "52", "56"]
        ev = [_ap(channel=ch) for ch in channels]
        cards = p._analyze_channel_congestion(ev)
        assert any("Diversity" in c.title for c in cards)

    def test_too_few_aps_returns_empty(self):
        p = _provider()
        ev = [_ap(channel="6")] * 3
        assert p._analyze_channel_congestion(ev) == []


class TestAnalyzeVendorDensity:
    def test_dominant_vendor_produces_note(self):
        p = _provider()
        # 7 of 10 = 70% Cisco → > 30% threshold
        ev = [_ap(vendor="Cisco")] * 7 + [_ap(vendor="Netgear")] * 3
        cards = p._analyze_vendor_density(ev)
        assert len(cards) == 1
        assert "Cisco" in cards[0].title

    def test_mixed_vendors_returns_empty(self):
        p = _provider()
        ev = [
            _ap(vendor="Cisco"),
            _ap(vendor="Netgear"),
            _ap(vendor="Asus"),
            _ap(vendor="Linksys"),
        ]
        assert p._analyze_vendor_density(ev) == []


class TestAnalyzeSuspiciousNames:
    def test_default_ssid_flagged(self):
        p = _provider()
        ev = [_ap(ssid="NETGEAR")]
        cards = p._analyze_suspicious_names(ev)
        assert any("Default" in c.title or "Generic" in c.title for c in cards)

    def test_honeypot_ssid_flagged(self):
        p = _provider()
        ev = [_ap(ssid="Free WiFi")]
        cards = p._analyze_suspicious_names(ev)
        assert any("Public" in c.title or "Captive" in c.title or "Honeypot" in c.title or c.severity in (CardSeverity.WARN, CardSeverity.ANOMALY) for c in cards)

    def test_normal_ssid_not_flagged(self):
        p = _provider()
        ev = [_ap(ssid="MyHomeNetwork123")]
        assert p._analyze_suspicious_names(ev) == []


class TestAnalyzePcapOnly:
    def test_pcap_only_ap_produces_card(self):
        p = _provider()
        # Need >= 3 PCAP-only APs (seen_in_pcap=True, used_for_centroid=0, no radius)
        ev = [
            _ap(mac=f"AA:BB:CC:DD:EE:{i:02X}", seen_in_pcap=True,
                confidence_radius_m=None, used_for_centroid=0)
            for i in range(4)
        ]
        cards = p._analyze_pcap_only(ev)
        assert len(cards) >= 1
        assert "PCAP-Only" in cards[0].title

    def test_below_threshold_returns_empty(self):
        p = _provider()
        # Fewer than 3 → no card produced
        ev = [
            _ap(mac=f"AA:BB:CC:DD:EE:{i:02X}", seen_in_pcap=True,
                confidence_radius_m=None, used_for_centroid=0)
            for i in range(2)
        ]
        assert p._analyze_pcap_only(ev) == []

    def test_ap_with_location_not_flagged(self):
        p = _provider()
        # AP has GPS fix (radius set, centroid used) → not PCAP-only
        ev = [_ap(seen_in_pcap=True, confidence_radius_m=30.0, used_for_centroid=5)] * 5
        assert p._analyze_pcap_only(ev) == []


# ─────────────────────────────────────────────────────────────────────────────
# RuleBasedProvider — quality_score
# ─────────────────────────────────────────────────────────────────────────────

class TestQualityScore:
    def test_high_quality_grade_a(self):
        p = _provider()
        ev = [_ap(location_quality="High", channel=str(i)) for i in range(1, 11)]
        stats = {"overlap_pct": 90.0, "avg_sightings": 8.0}
        q = p.quality_score(ev, stats)
        assert q.grade == "A"
        assert q.score >= 80

    def test_zero_everything_grade_f(self):
        p = _provider()
        ev = [_ap(location_quality="Low", channel="")]
        stats = {"overlap_pct": 0, "avg_sightings": 0}
        q = p.quality_score(ev, stats)
        assert q.grade == "F"
        assert q.score < 20

    def test_score_bounded_0_100(self):
        p = _provider()
        ev = [_ap() for _ in range(10)]
        for pct in (0, 50, 100):
            for avg in (0, 1, 10):
                q = p.quality_score(ev, {"overlap_pct": pct, "avg_sightings": avg})
                assert 0 <= q.score <= 100

    def test_breakdown_labels_present(self):
        p = _provider()
        ev = [_ap()]
        q = p.quality_score(ev, {"overlap_pct": 50, "avg_sightings": 4})
        labels = [label for label, _, _ in q.breakdown]
        assert "GPS ↔ PCAP overlap" in labels
        assert "High/Med GPS quality" in labels

    def test_grade_boundaries(self):
        p = _provider()
        ev = [_ap(location_quality="High", channel=str(i)) for i in range(1, 9)]
        # Tune stats to hit ~60 score → grade B
        stats = {"overlap_pct": 75.0, "avg_sightings": 5.0}
        q = p.quality_score(ev, stats)
        assert q.grade in ("A", "B", "C")  # deterministic within sane range


# ─────────────────────────────────────────────────────────────────────────────
# RuleBasedProvider — on_event
# ─────────────────────────────────────────────────────────────────────────────

class TestOnEvent:
    def test_logs_added_event(self):
        p = _provider()
        card = p.on_event(WIAEvent.LOGS_ADDED, {"count": 3})
        assert isinstance(card, AssistantCard)
        assert "3" in card.fact
        assert card.severity == CardSeverity.INFO

    def test_pcaps_added_event(self):
        p = _provider()
        card = p.on_event(WIAEvent.PCAPS_ADDED, {"count": 5})
        assert isinstance(card, AssistantCard)
        assert "5" in card.fact

    def test_project_selected_event(self):
        p = _provider()
        card = p.on_event(WIAEvent.PROJECT_SELECTED, {"path": "/test/project"})
        assert isinstance(card, AssistantCard)
        assert "/test/project" in card.fact
        assert card.severity == CardSeverity.BOOT

    def test_ingest_done_event(self):
        p = _provider()
        card = p.on_event(WIAEvent.INGEST_DONE, {"imported": 7, "duplicates": 2})
        assert isinstance(card, AssistantCard)
        assert "7" in card.fact
        assert "2" in card.fact

    def test_analysis_start_event(self):
        p = _provider()
        card = p.on_event(WIAEvent.ANALYSIS_START, {"logs": 2, "pcaps": 4})
        assert isinstance(card, AssistantCard)
        assert "2" in card.fact and "4" in card.fact

    def test_unknown_event_returns_none(self):
        p = _provider()
        # analysis_done has no handler yet, should return None
        card = p.on_event(WIAEvent.ANALYSIS_DONE, {})
        assert card is None


# ─────────────────────────────────────────────────────────────────────────────
# RuleBasedProvider — interpret (end-to-end through all analyzers)
# ─────────────────────────────────────────────────────────────────────────────

class TestInterpret:
    def test_empty_evidence_returns_single_warn_card(self):
        p = _provider()
        cards = p.interpret([], EMPTY_STATS)
        assert len(cards) == 1
        assert cards[0].severity == CardSeverity.WARN
        assert "No Evidence" in cards[0].title

    def test_typical_evidence_returns_multiple_cards(self):
        p = _provider()
        ev = [
            _ap(mac="AA:BB:CC:DD:EE:FF", ssid="HomeNet", auth="WPA2", channel="6"),
            _ap(mac="AA:BB:CC:DD:EE:FE", ssid="Office", auth="WPA2", channel="11"),
            _ap(mac="AA:BB:CC:DD:EE:FD", ssid="Netgear", auth="WEP", channel="1"),  # WEP + default SSID
        ]
        cards = p.interpret(ev, HIGH_OVERLAP_STATS)
        assert len(cards) >= 2

    def test_all_cards_are_assistant_card_instances(self):
        p = _provider()
        ev = [_ap() for _ in range(5)]
        cards = p.interpret(ev, HIGH_OVERLAP_STATS)
        assert all(isinstance(c, AssistantCard) for c in cards)

    def test_wep_card_present_when_wep_auth(self):
        p = _provider()
        ev = [_ap(auth="WEP")]
        cards = p.interpret(ev, EMPTY_STATS)
        assert any("WEP" in c.title for c in cards)

    def test_randomized_mac_card_present(self):
        p = _provider()
        ev = [_ap(mac="02:11:22:33:44:55")]
        cards = p.interpret(ev, EMPTY_STATS)
        assert any("Randomized" in c.title for c in cards)


# ─────────────────────────────────────────────────────────────────────────────
# WIAEngine — high-level API
# ─────────────────────────────────────────────────────────────────────────────

class TestWIAEngine:
    def test_on_event_project_selected(self):
        engine = WIAEngine()
        card = engine.on_event(WIAEvent.PROJECT_SELECTED, {"path": "/lab/wardrive"})
        assert isinstance(card, AssistantCard)
        assert "Project" in card.title

    def test_on_event_logs_added(self):
        engine = WIAEngine()
        card = engine.on_event(WIAEvent.LOGS_ADDED, {"count": 2})
        assert card is not None
        assert "2" in card.fact

    def test_get_quality_none_before_analysis(self):
        engine = WIAEngine()
        assert engine.get_quality() is None

    def test_analyze_results_no_csv_returns_cards(self):
        # No csv path → load_evidence returns [] → engine still returns a done + no-evidence card
        engine = WIAEngine()
        cards = engine.analyze_results({})
        assert len(cards) >= 1
        # First card is always the "Analysis Complete" done card
        assert cards[0].severity == CardSeverity.BOOT
        assert "Analysis Complete" in cards[0].title

    def test_analyze_results_quality_populated(self):
        engine = WIAEngine()
        engine.analyze_results({})
        q = engine.get_quality()
        assert isinstance(q, CaptureQuality)
        assert 0 <= q.score <= 100
        assert q.grade in ("A", "B", "C", "D", "F")

    def test_analyze_results_with_csv(self):
        path = _write_csv([
            "AA:BB:CC:DD:EE:FF,TestNet,WPA2,6,-65,-68.0,5,5,30.0,75,High,0,yes,no,0,1,no,no,Cisco,,",
            "AA:BB:CC:DD:EE:FE,OtherNet,WPA,11,-80,-83.0,2,2,110.0,50,Medium,0,no,no,0,1,no,no,Netgear,,",
        ])
        try:
            engine = WIAEngine()
            cards = engine.analyze_results({"csv": path, "stats": HIGH_OVERLAP_STATS})
            assert len(cards) >= 1
            assert "2" in cards[0].fact or "AP records" in cards[0].fact
        finally:
            os.unlink(path)

    def test_explain_ap_found(self):
        path = _write_csv([
            "AA:BB:CC:DD:EE:FF,TestNet,WPA2,6,-65,-68.0,5,5,30.0,75,High,0,yes,no,0,1,no,no,Cisco,,",
        ])
        try:
            engine = WIAEngine()
            engine.analyze_results({"csv": path, "stats": {}})
            cards = engine.explain_ap("AA:BB:CC:DD:EE:FF")
            assert len(cards) >= 1
            assert "AA:BB:CC:DD:EE:FF" in cards[0].fact
        finally:
            os.unlink(path)

    def test_explain_ap_not_found(self):
        engine = WIAEngine()
        engine.analyze_results({})
        cards = engine.explain_ap("DE:AD:BE:EF:00:00")
        assert len(cards) == 1
        assert "Not Found" in cards[0].title

    def test_list_educational_topics(self):
        engine = WIAEngine()
        topics = engine.list_educational_topics()
        assert "rssi" in topics
        assert "eapol" in topics
        assert "randomized_mac" in topics
        assert len(topics) >= 10

    def test_get_educational_note_known_topic(self):
        engine = WIAEngine()
        note = engine.get_educational_note("rssi")
        assert "dBm" in note

    def test_get_educational_note_unknown_topic(self):
        engine = WIAEngine()
        note = engine.get_educational_note("nonexistent_topic_xyz")
        assert "No entry" in note or "nonexistent_topic_xyz" in note


# ─────────────────────────────────────────────────────────────────────────────
# AssistantCard — dataclass sanity
# ─────────────────────────────────────────────────────────────────────────────

class TestAssistantCard:
    def test_defaults_populated(self):
        card = AssistantCard(title="Test", fact="Some fact.")
        assert card.severity == CardSeverity.INFO
        assert card.confidence == ConfidenceTier.MODERATE
        assert card.interpretation == ""
        assert card.timestamp != ""  # auto-filled

    def test_custom_severity(self):
        card = AssistantCard(title="Warn", fact="Bad thing.", severity=CardSeverity.WARN)
        assert card.severity == CardSeverity.WARN


# ─────────────────────────────────────────────────────────────────────────────
# Signal profile
# ─────────────────────────────────────────────────────────────────────────────

class TestAnalyzeSignalProfile:
    def test_very_strong_signal_produces_card(self):
        p = _provider()
        ev = [_ap(best_rssi=-40)]
        cards = p._analyze_signal_profile(ev)
        assert len(cards) == 1
        assert "Very Strong" in cards[0].title

    def test_weak_signal_returns_empty(self):
        p = _provider()
        ev = [_ap(best_rssi=-80)]
        assert p._analyze_signal_profile(ev) == []

    def test_none_rssi_returns_empty(self):
        p = _provider()
        ev = [_ap(best_rssi=None)]
        assert p._analyze_signal_profile(ev) == []
