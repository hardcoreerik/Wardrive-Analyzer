"""Tests for core/geo.py — centroid, risk, stability."""
from __future__ import annotations

import pytest

from core.geo import compute_centroid_and_confidence, stability_score, compute_risk
from core.parser_logs import Sighting


def _make_sighting(lat, lon, rssi=-70, acc_m=10.0) -> Sighting:
    return Sighting(
        mac="AA:BB:CC:DD:EE:00",
        ssid="SyntheticNet",
        auth="[WPA2-PSK-CCMP][ESS]",
        channel="6",
        rssi=rssi,
        lat=lat,
        lon=lon,
        acc_m=acc_m,
        first_seen="2024-01-15 10:00:00",
        source_file="test.csv",
    )


class TestComputeCentroid:
    def test_single_sighting(self):
        sightings = [_make_sighting(47.6, -122.3)]
        lat, lon, conf_m, used_n = compute_centroid_and_confidence(sightings)
        assert lat == pytest.approx(47.6, abs=0.001)
        assert lon == pytest.approx(-122.3, abs=0.001)
        assert used_n == 1

    def test_two_sightings_averages(self):
        sightings = [
            _make_sighting(47.6, -122.3, rssi=-60),
            _make_sighting(47.7, -122.4, rssi=-60),
        ]
        lat, lon, conf_m, used_n = compute_centroid_and_confidence(sightings)
        assert used_n >= 1
        assert 47.5 < lat < 47.8
        assert -122.5 < lon < -122.2

    def test_no_gps_returns_none(self):
        sightings = [_make_sighting(None, None)]
        lat, lon, conf_m, used_n = compute_centroid_and_confidence(sightings)
        assert lat is None

    def test_empty_returns_none(self):
        lat, lon, conf_m, used_n = compute_centroid_and_confidence([])
        assert lat is None
        # used_n is None when there are no valid sightings
        assert not used_n


class TestStabilityScore:
    def test_stable_cluster(self):
        # stability_score(conf_radius_m, n) — lower radius + more points = higher score
        score = stability_score(25.0, 5)
        assert isinstance(score, int)
        assert 0 <= score <= 100

    def test_high_confidence(self):
        score = stability_score(5.0, 20)
        assert score >= 50

    def test_none_radius(self):
        assert stability_score(None, 5) == 0

    def test_zero_points(self):
        assert stability_score(25.0, 0) == 0


class TestComputeRisk:
    def test_open_network_is_high_risk(self):
        # compute_risk(auth, ssid, best_rssi); auth must contain "OPEN" to score +3
        score = compute_risk("[OPEN][ESS]", "OpenNet", -50)
        assert score >= 3

    def test_wpa2_network_lower_risk(self):
        score_wpa2 = compute_risk("[WPA2-PSK-CCMP][ESS]", "SecureNet", -80)
        score_open = compute_risk("[OPEN][ESS]", "OpenNet", -50)
        assert score_wpa2 < score_open

    def test_wep_network_has_risk(self):
        score = compute_risk("[WEP][ESS]", "WeakNet", -70)
        assert score >= 3

    def test_hidden_adds_risk(self):
        score_hidden = compute_risk("[WPA2-PSK-CCMP][ESS]", "", -70)
        score_named = compute_risk("[WPA2-PSK-CCMP][ESS]", "Named", -70)
        assert score_hidden >= score_named

    def test_returns_int_or_float(self):
        result = compute_risk("[WPA2-PSK-CCMP][ESS]", "Net", -65)
        assert isinstance(result, (int, float))
