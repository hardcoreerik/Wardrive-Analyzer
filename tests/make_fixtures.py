"""
Generate synthetic PCAP fixtures for tests.
Run once: python tests/make_fixtures.py
"""
from __future__ import annotations

import os
import struct


FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def _pcap_global_header(linktype: int = 105) -> bytes:
    """DLT_IEEE802_11 = 105, DLT_IEEE802_11_RADIO = 127."""
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)


def _pcap_packet(payload: bytes, ts_sec: int = 1_000_000_000) -> bytes:
    return struct.pack("<IIII", ts_sec, 0, len(payload), len(payload)) + payload


def _beacon_frame(bssid_hex: str, ssid: str, channel: int = 6) -> bytes:
    """Minimal 802.11 Beacon frame (no radiotap)."""
    bssid = bytes.fromhex(bssid_hex.replace(":", ""))
    fc = b"\x80\x00"               # Frame Control: Beacon
    duration = b"\x00\x00"
    da = b"\xff\xff\xff\xff\xff\xff"
    sa = bssid
    seq = b"\x00\x00"
    timestamp = b"\x00" * 8
    interval = struct.pack("<H", 100)
    capabilities = struct.pack("<H", 0x0431)
    ssid_bytes = ssid.encode("ascii", errors="replace")[:32]
    ssid_ie = bytes([0x00, len(ssid_bytes)]) + ssid_bytes
    ds_ie = bytes([0x03, 0x01, channel])
    body = timestamp + interval + capabilities + ssid_ie + ds_ie
    return fc + duration + da + sa + bssid + seq + body


def _probe_response_frame(bssid_hex: str, ssid: str, channel: int = 6) -> bytes:
    """Minimal 802.11 Probe Response frame."""
    bssid = bytes.fromhex(bssid_hex.replace(":", ""))
    fc = b"\x50\x00"              # Frame Control: Probe Response
    duration = b"\x00\x00"
    da = b"\xff\xff\xff\xff\xff\xff"
    sa = bssid
    seq = b"\x10\x00"
    timestamp = b"\x00" * 8
    interval = struct.pack("<H", 100)
    capabilities = struct.pack("<H", 0x0431)
    ssid_bytes = ssid.encode("ascii", errors="replace")[:32]
    ssid_ie = bytes([0x00, len(ssid_bytes)]) + ssid_bytes
    ds_ie = bytes([0x03, 0x01, channel])
    body = timestamp + interval + capabilities + ssid_ie + ds_ie
    return fc + duration + da + sa + bssid + seq + body


def write_beacon_pcap(path: str) -> None:
    """PCAP with two beacon frames from two synthetic BSSIDs."""
    hdr = _pcap_global_header(105)
    pkt1 = _pcap_packet(_beacon_frame("AABBCCDDEEA0", "SyntheticBeacon1", 6), 1_000_000_000)
    pkt2 = _pcap_packet(_beacon_frame("AABBCCDDEEB0", "SyntheticBeacon2", 11), 1_000_000_001)
    with open(path, "wb") as f:
        f.write(hdr + pkt1 + pkt2)


def write_probe_resp_pcap(path: str) -> None:
    """PCAP with probe response frames."""
    hdr = _pcap_global_header(105)
    pkt1 = _pcap_packet(_probe_response_frame("AABBCCDDEEC0", "SyntheticProbe", 1), 1_000_000_002)
    with open(path, "wb") as f:
        f.write(hdr + pkt1)


def write_corrupted_pcap(path: str) -> None:
    """Intentionally invalid PCAP (bad magic, truncated)."""
    with open(path, "wb") as f:
        f.write(b"\xDE\xAD\xBE\xEF\x00\x01\x02\x03")


def write_empty_pcap(path: str) -> None:
    """Valid PCAP header but zero packets."""
    with open(path, "wb") as f:
        f.write(_pcap_global_header(105))


def main() -> None:
    os.makedirs(FIXTURES_DIR, exist_ok=True)
    write_beacon_pcap(os.path.join(FIXTURES_DIR, "beacon.pcap"))
    write_probe_resp_pcap(os.path.join(FIXTURES_DIR, "probe_resp.pcap"))
    write_corrupted_pcap(os.path.join(FIXTURES_DIR, "corrupted.pcap"))
    write_empty_pcap(os.path.join(FIXTURES_DIR, "empty.pcap"))
    print(f"Fixtures written to {FIXTURES_DIR}")


if __name__ == "__main__":
    main()
