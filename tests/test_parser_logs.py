"""Tests for core/parser_logs.py — WiGLE CSV ingest and dedupe."""
from __future__ import annotations

import os
import tempfile

import pytest

from core.parser_logs import load_wardrive_logs, Sighting


class TestLoadWardriveLogsValid:
    def test_parses_sample_csv(self, sample_csv):
        sightings, logfiles = load_wardrive_logs([sample_csv])
        # Four distinct MACs in the sample fixture
        assert len(sightings) == 4
        assert len(logfiles) == 4

    def test_dedupe_by_mac(self, sample_csv):
        """Same MAC seen twice should produce one key but multiple sightings."""
        sightings, logfiles = load_wardrive_logs([sample_csv])
        # AA:BB:CC:DD:EE:01 appears twice in sample_wardrive.csv
        mac = "AA:BB:CC:DD:EE:01"
        assert mac in sightings
        assert len(sightings[mac]) == 2

    def test_sighting_fields(self, sample_csv):
        sightings, _ = load_wardrive_logs([sample_csv])
        s: Sighting = sightings["AA:BB:CC:DD:EE:01"][0]
        assert s.ssid == "SyntheticNet"
        assert s.auth == "[WPA2-PSK-CCMP][ESS]"
        assert s.channel == "6"
        assert s.rssi == -65
        assert s.lat == pytest.approx(47.600000)
        assert s.lon == pytest.approx(-122.300000)

    def test_logfile_tracking(self, sample_csv):
        _, logfiles = load_wardrive_logs([sample_csv])
        mac = "AA:BB:CC:DD:EE:01"
        assert any("sample_wardrive" in f for f in logfiles[mac])

    def test_multiple_files_merged(self, sample_csv, wigle_csv):
        sightings, _ = load_wardrive_logs([sample_csv, wigle_csv])
        # Should have MACs from both files
        assert "AA:BB:CC:DD:EE:01" in sightings
        assert "AA:BB:CC:DD:EE:10" in sightings

    def test_wigle_export(self, wigle_csv):
        sightings, _ = load_wardrive_logs([wigle_csv])
        assert "AA:BB:CC:DD:EE:10" in sightings
        assert "AA:BB:CC:DD:EE:11" in sightings


class TestLoadWardriveLogsEdgeCases:
    def test_malformed_csv_does_not_crash(self, malformed_csv):
        """Malformed file must be silently skipped, no exception raised."""
        sightings, logfiles = load_wardrive_logs([malformed_csv])
        assert isinstance(sightings, dict)
        assert isinstance(logfiles, dict)

    def test_empty_csv_returns_empty(self, empty_csv):
        sightings, logfiles = load_wardrive_logs([empty_csv])
        assert len(sightings) == 0
        assert len(logfiles) == 0

    def test_missing_file_does_not_crash(self, tmp_path):
        """A path that doesn't exist must be silently skipped."""
        fake = str(tmp_path / "nonexistent.csv")
        sightings, logfiles = load_wardrive_logs([fake])
        assert isinstance(sightings, dict)

    def test_empty_file_list(self):
        sightings, logfiles = load_wardrive_logs([])
        assert len(sightings) == 0
        assert len(logfiles) == 0

    def test_status_cb_called(self, sample_csv):
        messages = []
        load_wardrive_logs([sample_csv], status_cb=messages.append)
        assert any("P4R51NG" in m or "parsing" in m.lower() or "L0G" in m for m in messages)


class TestGPSParsing:
    def test_lat_lon_parsed(self, sample_csv):
        sightings, _ = load_wardrive_logs([sample_csv])
        s = sightings["AA:BB:CC:DD:EE:01"][0]
        assert isinstance(s.lat, float)
        assert isinstance(s.lon, float)
        # Fixture coordinates are in the Pacific Northwest region (fictional)
        assert 40.0 < s.lat < 50.0
        assert -130.0 < s.lon < -100.0

    def test_acc_m_parsed(self, sample_csv):
        sightings, _ = load_wardrive_logs([sample_csv])
        s = sightings["AA:BB:CC:DD:EE:01"][0]
        assert s.acc_m == pytest.approx(5.0)

    def test_hidden_ssid(self, sample_csv):
        """Empty SSID cell should produce NO_DATA string."""
        sightings, _ = load_wardrive_logs([sample_csv])
        # AA:BB:CC:DD:EE:04 has empty SSID in fixture
        s = sightings["AA:BB:CC:DD:EE:04"][0]
        from core.constants import NO_DATA
        assert s.ssid == NO_DATA
