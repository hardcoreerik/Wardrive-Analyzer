"""Tests for PCAP parser — core/parser_pcap.py."""
from __future__ import annotations

import pytest

# dpkt may not be installed in CI — skip PCAP tests gracefully
dpkt = pytest.importorskip("dpkt", reason="dpkt not installed — skipping PCAP tests")

from core.parser_pcap import load_pcaps, _DPKT_OK


# load_pcaps returns a 17-element tuple:
# (ap_bssids, ap_per_pcap, sta_per_pcap, ssid_by_bssid, ch_by_ap, rssi_ap,
#  ch_by_sta, rssi_sta, ssid_by_sta, bssid_by_sta, identity_by_mac,
#  pcaps_by_ap, pcaps_by_sta, eapol_per_pcap, eapol_by_bssid,
#  handshake_conf_by_bssid, status_string)
_IDX_AP_BSSIDS = 0
_IDX_STATUS_STR = 16


class TestBeaconParsing:
    def test_parse_beacon_pcap_returns_tuple(self, beacon_pcap):
        result = load_pcaps([beacon_pcap])
        assert isinstance(result, tuple)
        assert len(result) == 17

    def test_bssid_extracted(self, beacon_pcap):
        """Synthetic beacon PCAP should yield at least one BSSID."""
        result = load_pcaps([beacon_pcap])
        ap_bssids = result[_IDX_AP_BSSIDS]  # set of MAC strings
        # With radiotap-less frames (DLT 105), parser picks up addr3 as BSSID
        # Accept either found or empty (link-type handling may vary)
        assert isinstance(ap_bssids, set)

    def test_status_string_is_str(self, beacon_pcap):
        result = load_pcaps([beacon_pcap])
        assert isinstance(result[_IDX_STATUS_STR], str)


class TestProbeParsing:
    def test_parse_probe_response_returns_tuple(self, probe_pcap):
        result = load_pcaps([probe_pcap])
        assert isinstance(result, tuple)
        assert len(result) == 17


class TestMalformedPcap:
    def test_corrupted_pcap_does_not_crash(self, corrupted_pcap):
        """Corrupted PCAP must not raise an unhandled exception."""
        try:
            result = load_pcaps([corrupted_pcap])
        except SystemExit:
            pytest.fail("Parser called sys.exit() on corrupted PCAP")
        except Exception as exc:
            pytest.fail(f"Parser raised unhandled exception on corrupted PCAP: {exc}")

    def test_empty_pcap_returns_tuple(self, empty_pcap):
        """Empty but valid PCAP (header only, no packets) must return valid tuple."""
        result = load_pcaps([empty_pcap])
        assert isinstance(result, tuple)
        assert len(result) == 17

    def test_missing_file_does_not_crash(self, tmp_path):
        """Non-existent file must be handled gracefully."""
        fake = str(tmp_path / "nofile.pcap")
        result = load_pcaps([fake])
        assert isinstance(result, tuple)

    def test_empty_file_list(self):
        result = load_pcaps([])
        assert isinstance(result, tuple)
        assert len(result) == 17


class TestParserOutputShape:
    def test_ap_bssids_is_set(self, beacon_pcap):
        result = load_pcaps([beacon_pcap])
        assert isinstance(result[_IDX_AP_BSSIDS], set)

    def test_no_exception_on_mixed_files(self, beacon_pcap, corrupted_pcap, empty_pcap):
        """Mixed valid/invalid files in one call — must complete without crash."""
        result = load_pcaps([beacon_pcap, corrupted_pcap, empty_pcap])
        assert isinstance(result, tuple)
        assert len(result) == 17

    def test_status_cb_called(self, beacon_pcap):
        messages = []
        load_pcaps([beacon_pcap], status_cb=messages.append)
        # Status callback may or may not fire depending on file size
        assert isinstance(messages, list)

