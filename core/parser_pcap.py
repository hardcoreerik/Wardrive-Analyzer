"""
Native PCAP parsing with dpkt — no tshark dependency.

Parses:
  - 802.11 Beacon frames        → AP BSSIDs, SSIDs, channel, RSSI
  - Probe Responses             → AP evidence
  - Probe/Assoc/Reassoc Requests → Station (client) evidence
  - EAPOL frames                → Handshake detection (NONE/EAPOL/PARTIAL/4WAY)

Falls back gracefully: if dpkt is unavailable or a file is unreadable, that file
is skipped and parsing continues.

ThreadPoolExecutor is used to parse multiple PCAP files in parallel.
"""
from __future__ import annotations

import os
import struct
import threading
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List, Optional, Set, Tuple

from .helpers import norm_mac, is_locally_administered

try:
    import dpkt
    _DPKT_OK = True
except ImportError:
    _DPKT_OK = False

# Per-file packet cap — prevents multi-minute hangs on huge raw captures (e.g. 100MB+ files).
# 802.11 management frames are ~300 bytes each; 2M packets ≈ ~600MB of 802.11 data max.
_MAX_PACKETS_PER_FILE = 2_000_000

# Files larger than this (bytes) get a status warning before parsing begins.
_LARGE_FILE_WARN_BYTES = 50 * 1024 * 1024  # 50 MB

_SSID_MAX_CHARS = 128


def _clean_ssid_text(text: str) -> str:
    cleaned = "".join(
        ch if (ch.isprintable() and ch not in "\x00\r\n\t") else "?"
        for ch in text
    )
    cleaned = cleaned.replace("\ufffd", "?").strip()
    if not cleaned:
        return "<HIDDEN>"
    if len(cleaned) > _SSID_MAX_CHARS:
        return cleaned[:_SSID_MAX_CHARS] + "...[truncated]"
    return cleaned


# ---------------------------------------------------------------------------
# Frame-type constants (802.11)
# ---------------------------------------------------------------------------
_MGMT = 0x00
_SUBTYPE_ASSOC_REQ    = 0x00
_SUBTYPE_REASSOC_REQ  = 0x02
_SUBTYPE_PROBE_REQ    = 0x04
_SUBTYPE_PROBE_RESP   = 0x05
_SUBTYPE_BEACON       = 0x08

# EAPOL EtherType (in 802.11 data frames via LLC/SNAP or raw)
_EAPOL_ETHERTYPE = 0x888E


def _freq_to_channel(freq_mhz: int) -> Optional[int]:
    if 2412 <= freq_mhz <= 2472:
        return (freq_mhz - 2412) // 5 + 1
    if freq_mhz == 2484:
        return 14
    if 5000 <= freq_mhz <= 5900:
        return (freq_mhz - 5000) // 5
    if 5925 <= freq_mhz <= 7125:
        return (freq_mhz - 5950) // 5
    return None


def _parse_radiotap_rssi_freq(buf: bytes) -> Tuple[Optional[int], Optional[int]]:
    """
    Quick radiotap header parser for RSSI (dBm antenna signal) and channel freq.
    Returns (rssi_dbm, freq_mhz). Both may be None.
    """
    if len(buf) < 8:
        return None, None
    try:
        it_len = struct.unpack_from("<H", buf, 2)[0]
        it_present = struct.unpack_from("<I", buf, 4)[0]

        rssi: Optional[int] = None
        freq: Optional[int] = None

        # Walk present words to find extended present masks
        present_offset = 4
        present_words = [it_present]
        while present_words[-1] & (1 << 31) and present_offset + 4 < it_len:
            present_offset += 4
            if present_offset + 4 > len(buf):
                break
            present_words.append(struct.unpack_from("<I", buf, present_offset)[0])

        data_offset = present_offset + 4
        first = present_words[0]

        # Bit 0: TSFT (8 bytes, align 8)
        if first & (1 << 0):
            data_offset = (data_offset + 7) & ~7
            data_offset += 8
        # Bit 1: Flags (1 byte)
        if first & (1 << 1):
            data_offset += 1
        # Bit 2: Rate (1 byte)
        if first & (1 << 2):
            data_offset += 1
        # Bit 3: Channel (4 bytes: freq u16 + flags u16), align 2
        if first & (1 << 3):
            data_offset = (data_offset + 1) & ~1
            if data_offset + 4 <= len(buf):
                freq = struct.unpack_from("<H", buf, data_offset)[0]
            data_offset += 4
        # Bit 4: FHSS (2 bytes)
        if first & (1 << 4):
            data_offset += 2
        # Bit 5: dBm Antenna Signal (1 byte, signed)
        if first & (1 << 5):
            if data_offset < len(buf):
                raw = buf[data_offset]
                rssi = raw if raw < 128 else raw - 256
            data_offset += 1

        return rssi, freq
    except Exception:
        return None, None


def _parse_ssid_from_ie(payload: bytes) -> str:
    """Extract SSID from 802.11 information elements."""
    i = 0
    while i + 2 <= len(payload):
        ie_id = payload[i]
        ie_len = payload[i + 1]
        if i + 2 + ie_len > len(payload):
            break
        if ie_id == 0:  # SSID IE
            raw = payload[i + 2: i + 2 + ie_len]
            try:
                return _clean_ssid_text(raw.decode("utf-8", errors="replace"))
            except Exception:
                return "<HIDDEN>"
        i += 2 + ie_len
    return "<HIDDEN>"


def _mac_bytes_to_str(b: bytes) -> str:
    return ":".join(f"{x:02X}" for x in b)


# ---------------------------------------------------------------------------
# Per-file parser (runs in worker thread)
# ---------------------------------------------------------------------------

class _PerFileResult:
    __slots__ = (
        "pcap_name",
        "ap_counts", "sta_counts",
        "ssid_hits",          # bssid -> {ssid -> count}
        "ch_hits_ap",         # bssid -> {ch -> count}
        "rssi_best_ap",       # bssid -> int
        "ch_hits_sta",        # sta   -> {ch -> count}
        "rssi_best_sta",      # sta   -> int
        "eapol_count",        # int
        "eapol_bssids",       # bssid -> count
        "eapol_msgs",         # bssid -> set of msg numbers
        "error",
    )

    def __init__(self, pcap_name: str):
        self.pcap_name = pcap_name
        self.ap_counts: Counter = Counter()
        self.sta_counts: Counter = Counter()
        self.ssid_hits: Dict[str, Counter] = defaultdict(Counter)
        self.ch_hits_ap: Dict[str, Counter] = defaultdict(Counter)
        self.rssi_best_ap: Dict[str, int] = {}
        self.ch_hits_sta: Dict[str, Counter] = defaultdict(Counter)
        self.rssi_best_sta: Dict[str, int] = {}
        self.eapol_count: int = 0
        self.eapol_bssids: Counter = Counter()
        self.eapol_msgs: Dict[str, set] = defaultdict(set)
        self.error: str = ""


def _parse_one_pcap(pcap_path: str) -> _PerFileResult:
    name = os.path.basename(pcap_path)
    result = _PerFileResult(name)

    if not _DPKT_OK:
        result.error = "dpkt not installed"
        return result

    try:
        file_size = os.path.getsize(pcap_path)
        if file_size > _LARGE_FILE_WARN_BYTES:
            result.error = f"large file ({file_size // (1024*1024)}MB) — parsing capped at {_MAX_PACKETS_PER_FILE:,} packets"

        with open(pcap_path, "rb") as f:
            try:
                cap = dpkt.pcap.Reader(f)
            except Exception:
                try:
                    f.seek(0)
                    cap = dpkt.pcapng.Reader(f)
                except Exception as e:
                    result.error = str(e)
                    return result

            packet_count = 0
            for _ts, buf in cap:
                _process_frame(buf, result)
                packet_count += 1
                if packet_count >= _MAX_PACKETS_PER_FILE:
                    if not result.error:
                        result.error = f"truncated at {_MAX_PACKETS_PER_FILE:,} packets"
                    break
    except Exception as e:
        result.error = str(e)

    return result


def _process_frame(buf: bytes, r: _PerFileResult) -> None:
    """Decode one raw 802.11 frame (with radiotap header) and update result."""
    if len(buf) < 4:
        return

    try:
        rt_len = struct.unpack_from("<H", buf, 2)[0]
        if rt_len > len(buf):
            return

        rssi, freq = _parse_radiotap_rssi_freq(buf[:rt_len])
        ch = _freq_to_channel(freq) if freq else None
        frame = buf[rt_len:]

        if len(frame) < 2:
            return

        fc = struct.unpack_from("<H", frame, 0)[0]
        ftype = (fc >> 2) & 0x3
        fsubtype = (fc >> 4) & 0xF

        if ftype == _MGMT:
            _process_mgmt(frame, fsubtype, rssi, ch, r)
        elif ftype == 0x02:  # Data
            _process_data(frame, r)
    except Exception:
        pass


def _process_mgmt(frame: bytes, subtype: int, rssi: Optional[int], ch: Optional[int], r: _PerFileResult) -> None:
    if len(frame) < 24:
        return

    addr1 = _mac_bytes_to_str(frame[4:10])   # RA/DA
    addr2 = _mac_bytes_to_str(frame[10:16])  # TA/SA
    addr3 = _mac_bytes_to_str(frame[16:22])  # BSSID for mgmt

    if subtype in (_SUBTYPE_BEACON, _SUBTYPE_PROBE_RESP):
        bssid = norm_mac(addr3)
        if not bssid:
            return
        r.ap_counts[bssid] += 1
        payload = frame[24:]
        if subtype == _SUBTYPE_BEACON and len(payload) >= 12:
            payload = payload[12:]  # skip fixed fields (timestamp 8, interval 2, capability 2)
        ssid = _parse_ssid_from_ie(payload)
        r.ssid_hits[bssid][ssid] += 1
        if ch is not None:
            r.ch_hits_ap[bssid][str(ch)] += 1
        if rssi is not None:
            if bssid not in r.rssi_best_ap or rssi > r.rssi_best_ap[bssid]:
                r.rssi_best_ap[bssid] = rssi

    elif subtype in (_SUBTYPE_PROBE_REQ, _SUBTYPE_ASSOC_REQ, _SUBTYPE_REASSOC_REQ):
        sta = norm_mac(addr2)
        if not sta:
            return
        r.sta_counts[sta] += 1
        if ch is not None:
            r.ch_hits_sta[sta][str(ch)] += 1
        if rssi is not None:
            if sta not in r.rssi_best_sta or rssi > r.rssi_best_sta[sta]:
                r.rssi_best_sta[sta] = rssi


def _process_data(frame: bytes, r: _PerFileResult) -> None:
    """Detect EAPOL in data frames (LLC/SNAP + EtherType 0x888E)."""
    if len(frame) < 26:
        return
    fc = struct.unpack_from("<H", frame, 0)[0]
    # To-DS / From-DS bits
    to_ds = (fc >> 8) & 0x1
    from_ds = (fc >> 9) & 0x1

    # Addr1=RA, Addr2=TA, Addr3=DA or SA depending on DS bits
    addr1 = _mac_bytes_to_str(frame[4:10])
    addr2 = _mac_bytes_to_str(frame[10:16])
    addr3 = _mac_bytes_to_str(frame[16:22])

    if to_ds and from_ds:
        bssid = ""
    elif to_ds:
        bssid = addr1  # RA = BSSID
    elif from_ds:
        bssid = addr2  # TA = BSSID
    else:
        bssid = addr3

    bssid = norm_mac(bssid)

    # 802.11 header is 24 bytes; QoS adds 2
    header_len = 26 if (fc >> 4) & 0xF in (0x8, 0xA, 0xC, 0xE) else 24
    body = frame[header_len:]

    # LLC/SNAP: AA AA 03 00 00 00 <EtherType 2 bytes>
    if len(body) >= 8 and body[0] == 0xAA and body[1] == 0xAA and body[2] == 0x03:
        etype = struct.unpack_from(">H", body, 6)[0]
        if etype == _EAPOL_ETHERTYPE:
            r.eapol_count += 1
            if bssid:
                r.eapol_bssids[bssid] += 1
                # EAPOL key descriptor: body[8] = version, body[9] = type (3=key), body[10..] = key info
                eapol_body = body[8:]
                if len(eapol_body) >= 4 and eapol_body[1] == 3:
                    key_info = struct.unpack_from(">H", eapol_body, 2)[0] if len(eapol_body) >= 4 else 0
                    # Message number heuristic via key_info bits
                    install = bool(key_info & 0x0040)
                    ack = bool(key_info & 0x0080)
                    mic = bool(key_info & 0x0100)
                    secure = bool(key_info & 0x0200)
                    if ack and not mic and not secure:
                        r.eapol_msgs[bssid].add(1)
                    elif not ack and mic and not secure:
                        r.eapol_msgs[bssid].add(2)
                    elif ack and mic and not secure:
                        r.eapol_msgs[bssid].add(3)
                    elif not ack and mic and secure:
                        r.eapol_msgs[bssid].add(4)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_pcaps(
    pcap_files: List[str],
    status_cb: Optional[Callable[[str], None]] = None,
    max_workers: int = 4,
) -> Tuple[
    Set[str],
    Dict[str, Counter],
    Dict[str, Counter],
    Dict[str, Counter],
    Dict[str, Counter],
    Dict[str, int],
    Dict[str, Counter],
    Dict[str, int],
    Dict[str, Set[str]],
    Dict[str, Set[str]],
    Dict[str, int],
    Dict[str, int],
    Dict[str, str],
    str,
]:
    """
    Parse all PCAP files in parallel using dpkt.

    Returns the same 14-tuple as the legacy load_pcaps_tshark for drop-in compat:
      ap_bssids, ap_per_pcap_counts, sta_per_pcap_counts,
      ssid_counts_by_bssid, ch_counts_by_ap, best_rssi_by_ap,
      ch_counts_by_sta, best_rssi_by_sta,
      pcaps_by_ap, pcaps_by_sta,
      eapol_per_pcap, eapol_by_bssid, handshake_conf_by_bssid,
      status_string
    """
    if not _DPKT_OK:
        empty: Tuple = (
            set(), {}, {}, defaultdict(Counter), defaultdict(Counter), {},
            defaultdict(Counter), {}, defaultdict(set), defaultdict(set),
            {}, {}, {}, "dpkt not installed — PCAP parsing skipped.",
        )
        return empty  # type: ignore[return-value]

    ap_bssids: Set[str] = set()
    ap_per_pcap: Dict[str, Counter] = {}
    sta_per_pcap: Dict[str, Counter] = {}
    ssid_by_bssid: Dict[str, Counter] = defaultdict(Counter)
    ch_by_ap: Dict[str, Counter] = defaultdict(Counter)
    rssi_ap: Dict[str, int] = {}
    ch_by_sta: Dict[str, Counter] = defaultdict(Counter)
    rssi_sta: Dict[str, int] = {}
    pcaps_by_ap: Dict[str, Set[str]] = defaultdict(set)
    pcaps_by_sta: Dict[str, Set[str]] = defaultdict(set)
    eapol_per_pcap: Dict[str, int] = {}
    eapol_by_bssid: Dict[str, int] = defaultdict(int)
    msg_by_bssid: Dict[str, set] = defaultdict(set)

    total = len(pcap_files)
    lock = threading.Lock()
    completed = [0]

    # Warn up front about large files so the user sees them before the parser blocks.
    if status_cb:
        for p in pcap_files:
            try:
                sz = os.path.getsize(p)
                if sz > _LARGE_FILE_WARN_BYTES:
                    status_cb(
                        f"    [warn] large file ({sz // (1024*1024)}MB) — "
                        f"will cap at {_MAX_PACKETS_PER_FILE:,} packets: {os.path.basename(p)}"
                    )
            except OSError:
                pass

    def _work(path: str) -> _PerFileResult:
        return _parse_one_pcap(path)

    with ThreadPoolExecutor(max_workers=min(max_workers, max(1, total))) as ex:
        futures = {ex.submit(_work, p): p for p in pcap_files}
        for future in as_completed(futures):
            res: _PerFileResult = future.result()
            with lock:
                completed[0] += 1
                if status_cb:
                    status_cb(f"[*] P4R51NG PCAP {completed[0]}/{total}: {res.pcap_name}")
                if res.error and status_cb:
                    status_cb(f"    [warn] {res.pcap_name}: {res.error}")

                ap_per_pcap[res.pcap_name] = res.ap_counts
                sta_per_pcap[res.pcap_name] = res.sta_counts

                for bssid, count in res.ap_counts.items():
                    ap_bssids.add(bssid)
                    pcaps_by_ap[bssid].add(res.pcap_name)

                for bssid, cnt in res.ssid_hits.items():
                    ssid_by_bssid[bssid].update(cnt)
                for bssid, cnt in res.ch_hits_ap.items():
                    ch_by_ap[bssid].update(cnt)
                for bssid, rssi in res.rssi_best_ap.items():
                    if bssid not in rssi_ap or rssi > rssi_ap[bssid]:
                        rssi_ap[bssid] = rssi

                for sta in res.sta_counts:
                    pcaps_by_sta[sta].add(res.pcap_name)
                for sta, cnt in res.ch_hits_sta.items():
                    ch_by_sta[sta].update(cnt)
                for sta, rssi in res.rssi_best_sta.items():
                    if sta not in rssi_sta or rssi > rssi_sta[sta]:
                        rssi_sta[sta] = rssi

                eapol_per_pcap[res.pcap_name] = res.eapol_count
                for bssid, cnt in res.eapol_bssids.items():
                    eapol_by_bssid[bssid] += cnt
                for bssid, msgs in res.eapol_msgs.items():
                    msg_by_bssid[bssid].update(msgs)

    # Handshake confidence
    handshake_conf: Dict[str, str] = {}
    for b in set(list(eapol_by_bssid.keys()) + list(msg_by_bssid.keys())):
        msgs = msg_by_bssid.get(b, set())
        if {1, 2, 3, 4}.issubset(msgs):
            handshake_conf[b] = "4WAY"
        elif msgs:
            handshake_conf[b] = "PARTIAL"
        elif eapol_by_bssid.get(b, 0) > 0:
            handshake_conf[b] = "EAPOL"
        else:
            handshake_conf[b] = "NONE"

    return (
        ap_bssids,
        ap_per_pcap,
        sta_per_pcap,
        ssid_by_bssid,
        ch_by_ap,
        rssi_ap,
        ch_by_sta,
        rssi_sta,
        pcaps_by_ap,
        pcaps_by_sta,
        eapol_per_pcap,
        dict(eapol_by_bssid),
        handshake_conf,
        "dpkt OK (parallel)",
    )
