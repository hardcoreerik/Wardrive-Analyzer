from __future__ import annotations

import os
import re
import shutil
import hashlib
import sqlite3
import csv
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Literal, Tuple

APP_ID = "WardriveAlpha"
DB_NAME = "project.db"

SourceApp = Literal["marauder", "porkchop", "bruce", "nemo", "unknown"]


@dataclass
class CandidateFile:
    abs_path: str
    rel_path: str
    filename: str
    ext: str
    source_app: SourceApp
    kind: str
    recommended: bool
    reason: str
    size: int


# --- patterns / allow-lists ---

# Marauder numbered PCAP outputs  (e.g. beacon_0.pcap, raw_1.pcap)
_MARAUDER_PCAP_PREFIXES = (
    "raw_",
    "beacon_",
    "probe_",
    "ap_",
    "station_",
    "ap_sta_",
    "packet_monitor_",
    "multissid_",
    "deauth_",
    "sae_commit_",
    "flock_",       # Flock module captures
    "yoink_",       # Yoink module captures
    "jammit_",      # Jammit module root-level pcaps
)

# Marauder .log / .txt outputs (WiGLE CSV format or scan logs)
_MARAUDER_LOG_PREFIXES = (
    "wardrive_",
    "station_wardrive_",
    "flock_wardrive_",
    "pingscan_",
    "arpscan_",
    "portscan_",
    "sshscan_",
    "telnetscan_",
    "dns_",
    "http_",
    "https_",
    "yoink_",       # Yoink session logs (metadata, not WiGLE CSV)
    "jammit_",      # Jammit session logs (metadata)
    "recon_",       # Recon scan outputs
    "flock_",       # Flock session logs
)

# Marauder scan outputs in CSV format (not WiGLE, not log extension)
_MARAUDER_CSV_PREFIXES = (
    "portscan_",
    "arpscan_",
    "pingscan_",
    "recon_",
    "sshscan_",
    "telnetscan_",
    "stats",        # Jammit per-second stats.csv
)

# Jammit per-target capture session: known bare filenames produced inside SSID_BSSID/ dirs
_JAMMIT_PCAP_NAMES = {"beacon.pcap", "handshakes.pcap", "raw.pcap", "jammit_deauths.pcap"}
_JAMMIT_META_NAMES = {"capture_summary.txt", "jammit_session.log", "stats.csv"}

# Regex: a directory named  <something>_XX-XX-XX-XX-XX-XX  (Jammit per-target folder)
_JAMMIT_TARGET_DIR_RE = re.compile(
    r"(?:^|/)captures/[^/]+_[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}(?:/|$)",
    re.IGNORECASE,
)

# Kinds that are NOT wardrive/GPS data — exclude from log analysis input
_NON_WARDRIVE_LOG_KINDS = {
    "jammit_session", "yoink_session", "jammit_summary",
    "jammit_stats",   "jammit_other",  "recon_csv",
    "log_yoink",      "log_jammit",    "log_flock",
}

_BRUCE_FILES_RECOMMENDED = {"bruce_creds.csv"}
_BRUCE_FILES_OPTIONAL = {"bruce.conf", "shortcuts.json", "boot.jpg", "boot.gif", "boot.wav"}

# Files/folders we should *not* ingest when the SD also contains our own project/runs/reports.
_PROJECT_OUTPUT_FILENAMES = {
    "summary.html",
    "map.html",
    "wardrive_map.kml",
    "pcap_summary.html",
    "pcap_bssid_master.csv",
    "pcap_station_master.csv",
    "pcap_per_file_summary.csv",
    "pcap_bssid_master.xlsx",
    "pcap_station_master.xlsx",
    "project.db",
}

_PROJECT_OUTPUT_DIRNAMES = {"runs", "exports", "evidence", ".git", "__pycache__", "dist", "build"}


def ensure_project_vault(project_dir: str) -> str:
    """Ensure Option A folder layout + SQLite DB. Returns DB path."""
    os.makedirs(project_dir, exist_ok=True)
    os.makedirs(os.path.join(project_dir, "evidence", "imports"), exist_ok=True)
    os.makedirs(os.path.join(project_dir, "exports", "wigle"), exist_ok=True)
    os.makedirs(os.path.join(project_dir, "exports", "wpa-sec"), exist_ok=True)
    os.makedirs(os.path.join(project_dir, "runs"), exist_ok=True)

    db_path = os.path.join(project_dir, DB_NAME)
    conn = sqlite3.connect(db_path)
    try:
        _init_db(conn)
    finally:
        conn.close()
    return db_path


def _init_db(conn: sqlite3.Connection) -> None:
    c = conn.cursor()
    c.execute(
        "CREATE TABLE IF NOT EXISTS imports ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "created_utc TEXT NOT NULL,"
        "source_path TEXT NOT NULL,"
        "label TEXT)"
    )
    c.execute(
        "CREATE TABLE IF NOT EXISTS evidence_files ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "import_id INTEGER NOT NULL,"
        "original_path TEXT NOT NULL,"
        "stored_path TEXT NOT NULL,"
        "rel_path TEXT NOT NULL,"
        "sha256 TEXT NOT NULL,"
        "size INTEGER NOT NULL,"
        "mtime_ns INTEGER NOT NULL,"
        "source_app TEXT NOT NULL,"
        "kind TEXT NOT NULL,"
        "recommended INTEGER NOT NULL DEFAULT 0,"
        "is_duplicate INTEGER NOT NULL DEFAULT 0,"
        "FOREIGN KEY(import_id) REFERENCES imports(id))"
    )
    c.execute("CREATE INDEX IF NOT EXISTS idx_evidence_sha ON evidence_files(sha256)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_evidence_kind ON evidence_files(kind)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_evidence_app ON evidence_files(source_app)")
    c.execute("CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v TEXT NOT NULL)")
    conn.commit()


def set_setting(db_path: str, key: str, value: str) -> None:
    conn = sqlite3.connect(db_path)
    try:
        c = conn.cursor()
        c.execute(
            "INSERT INTO settings(k,v) VALUES(?,?) "
            "ON CONFLICT(k) DO UPDATE SET v=excluded.v",
            (key, value),
        )
        conn.commit()
    finally:
        conn.close()


def get_setting(db_path: str, key: str, default: str = "") -> str:
    conn = sqlite3.connect(db_path)
    try:
        c = conn.cursor()
        c.execute("SELECT v FROM settings WHERE k=?", (key,))
        row = c.fetchone()
        return row[0] if row else default
    finally:
        conn.close()


def sha256_exists(db_path: str, sha256: str) -> bool:
    """Return True if this sha256 is already recorded in the project evidence DB."""
    if not sha256:
        return False
    if not os.path.exists(db_path):
        return False
    conn = sqlite3.connect(db_path)
    try:
        c = conn.cursor()
        c.execute("SELECT 1 FROM evidence_files WHERE sha256=? LIMIT 1", (sha256,))
        return c.fetchone() is not None
    finally:
        conn.close()


def project_db_stats(project_dir: str) -> Dict[str, int]:
    """Small stats snapshot for UI messaging."""
    db_path = os.path.join(project_dir, DB_NAME)
    if not os.path.exists(db_path):
        return {"imports": 0, "evidence": 0}
    conn = sqlite3.connect(db_path)
    try:
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM imports")
        imports = int(c.fetchone()[0])
        c.execute("SELECT COUNT(*) FROM evidence_files")
        evidence = int(c.fetchone()[0])
        return {"imports": imports, "evidence": evidence}
    finally:
        conn.close()


def list_import_history(project_dir: str, limit: int = 100) -> List[Dict[str, str]]:
    """Return recent imports for Mission Control views."""
    db_path = ensure_project_vault(project_dir)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        c = conn.cursor()
        c.execute(
            "SELECT i.id, i.created_utc, i.source_path, i.label, COUNT(e.id) AS file_count "
            "FROM imports i LEFT JOIN evidence_files e ON e.import_id=i.id "
            "GROUP BY i.id "
            "ORDER BY i.id DESC "
            "LIMIT ?",
            (int(limit),),
        )
        return [dict(r) for r in c.fetchall()]
    finally:
        conn.close()


def evidence_summary(project_dir: str) -> Dict[str, object]:
    """Return dashboard-friendly evidence totals without mutating project data."""
    db_path = ensure_project_vault(project_dir)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM evidence_files")
        total = int(c.fetchone()[0])
        c.execute("SELECT COUNT(*) FROM evidence_files WHERE is_duplicate=1")
        duplicates = int(c.fetchone()[0])
        c.execute("SELECT source_app, COUNT(*) AS n FROM evidence_files GROUP BY source_app ORDER BY source_app")
        by_source = {str(r["source_app"]): int(r["n"]) for r in c.fetchall()}
        c.execute("SELECT kind, COUNT(*) AS n FROM evidence_files GROUP BY kind ORDER BY kind")
        by_kind = {str(r["kind"]): int(r["n"]) for r in c.fetchall()}
        c.execute(
            "SELECT created_utc, source_path, label FROM imports "
            "ORDER BY id DESC LIMIT 1"
        )
        row = c.fetchone()
        latest_import = dict(row) if row else {}
        return {
            "total": total,
            "duplicates": duplicates,
            "by_source": by_source,
            "by_kind": by_kind,
            "latest_import": latest_import,
        }
    finally:
        conn.close()


def list_project_evidence_detailed(project_dir: str) -> List[Dict[str, object]]:
    """Return evidence rows joined with import metadata for the Evidence Vault."""
    db_path = ensure_project_vault(project_dir)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        c = conn.cursor()
        c.execute(
            "SELECT e.id, e.stored_path, e.rel_path, e.kind, e.source_app, e.sha256, "
            "e.size, e.recommended, e.is_duplicate, i.created_utc, i.source_path, i.label "
            "FROM evidence_files e LEFT JOIN imports i ON i.id=e.import_id "
            "ORDER BY e.source_app, e.kind, e.rel_path"
        )
        return [dict(r) for r in c.fetchall()]
    finally:
        conn.close()


def _find_first_file(root: str, filename: str) -> str:
    direct = os.path.join(root, filename)
    if os.path.exists(direct):
        return direct
    for dirpath, _dirnames, filenames in os.walk(root):
        if filename in filenames:
            return os.path.join(dirpath, filename)
    return ""


def discover_project_runs(project_dir: str) -> List[Dict[str, object]]:
    """Discover run folders and output files, tolerating older nested run layouts."""
    runs_dir = os.path.join(project_dir, "runs")
    if not os.path.isdir(runs_dir):
        return []

    expected = [
        "summary.html",
        "map.html",
        "wardrive_map.kml",
        "wardrive_master.csv",
        "wardrive_master.xlsx",
        "pcap_summary.html",
        "pcap_bssid_master.csv",
        "pcap_bssid_master.xlsx",
        "pcap_station_master.csv",
        "pcap_station_master.xlsx",
        "pcap_per_file_summary.csv",
    ]
    runs: List[Dict[str, object]] = []
    for name in os.listdir(runs_dir):
        path = os.path.join(runs_dir, name)
        if not os.path.isdir(path) or not name.lower().startswith("run_"):
            continue
        outputs = {fn: _find_first_file(path, fn) for fn in expected}
        present = [fn for fn, p in outputs.items() if p]
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            mtime = 0.0
        runs.append(
            {
                "run_id": name,
                "run_dir": path,
                "modified": datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S") if mtime else "",
                "outputs": outputs,
                "present_count": len(present),
                "missing": [fn for fn in expected if not outputs.get(fn)],
            }
        )
    runs.sort(key=lambda r: str(r.get("modified", "")), reverse=True)
    return runs


def _read_master_csv(path: str) -> Dict[str, Dict[str, str]]:
    rows: Dict[str, Dict[str, str]] = {}
    if not path or not os.path.exists(path):
        return rows
    with open(path, "r", newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            mac = (row.get("MAC") or row.get("BSSID") or "").strip().upper()
            if mac:
                rows[mac] = {str(k): str(v) for k, v in row.items()}
    return rows


def compare_run_masters(new_csv: str, old_csv: str) -> Dict[str, object]:
    """Compare two wardrive_master.csv files by normalized MAC/BSSID."""
    new_rows = _read_master_csv(new_csv)
    old_rows = _read_master_csv(old_csv)
    new_keys = set(new_rows.keys())
    old_keys = set(old_rows.keys())
    added = sorted(new_keys - old_keys)
    missing = sorted(old_keys - new_keys)
    changed: List[Dict[str, str]] = []
    for mac in sorted(new_keys & old_keys):
        n = new_rows[mac]
        o = old_rows[mac]
        diffs = []
        for field in ("TopSSID", "SSID", "AuthMode", "Auth", "Channel"):
            if (n.get(field) or "") != (o.get(field) or ""):
                diffs.append(field)
        if diffs:
            changed.append(
                {
                    "MAC": mac,
                    "fields": ", ".join(diffs),
                    "old": " | ".join([o.get("TopSSID", o.get("SSID", "")), o.get("AuthMode", o.get("Auth", "")), o.get("Channel", "")]),
                    "new": " | ".join([n.get("TopSSID", n.get("SSID", "")), n.get("AuthMode", n.get("Auth", "")), n.get("Channel", "")]),
                }
            )
    return {
        "new_total": len(new_rows),
        "old_total": len(old_rows),
        "added_count": len(added),
        "missing_count": len(missing),
        "changed_count": len(changed),
        "added": added,
        "missing": missing,
        "changed": changed,
    }


def sha256_file(path: str, chunk_size: int = 1024 * 1024, progress_cb=None) -> str:
    """SHA-256 a file in chunks. progress_cb(bytes_done, bytes_total) called each chunk."""
    h = hashlib.sha256()
    total = os.path.getsize(path)
    done = 0
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk_size)
            if not b:
                break
            h.update(b)
            done += len(b)
            if progress_cb:
                progress_cb(done, total)
    return h.hexdigest()


def _copy_with_progress(src: str, dst: str, progress_cb=None,
                        chunk_size: int = 512 * 1024) -> None:
    """Copy src → dst in chunks, calling progress_cb(bytes_done, bytes_total) each chunk."""
    total = os.path.getsize(src)
    done = 0
    with open(src, "rb") as fsrc, open(dst, "wb") as fdst:
        while True:
            buf = fsrc.read(chunk_size)
            if not buf:
                break
            fdst.write(buf)
            done += len(buf)
            if progress_cb:
                progress_cb(done, total)
    shutil.copystat(src, dst)


def looks_like_project_dir(dir_path: str) -> bool:
    if os.path.isfile(os.path.join(dir_path, DB_NAME)):
        return True
    for name in ("runs", "exports", "evidence"):
        if os.path.isdir(os.path.join(dir_path, name)):
            return True
    for fn in ("summary.html", "map.html", "wardrive_map.kml"):
        if os.path.isfile(os.path.join(dir_path, fn)):
            return True
    return False


def should_skip_dir(dir_path: str) -> bool:
    base = os.path.basename(dir_path).lower()
    if base in _PROJECT_OUTPUT_DIRNAMES:
        return True
    if looks_like_project_dir(dir_path):
        return True
    return False


def _in_jammit_capture_dir(rel_lower: str) -> bool:
    """True if this path is inside a Jammit per-target capture directory."""
    # Matches  captures/<any>  whether the dir uses dashes or not
    return "/captures/" in rel_lower or rel_lower.startswith("captures/")


def classify_candidate(rel_path: str, filename: str) -> Tuple[SourceApp, str, bool, str]:
    """Return (source_app, kind, recommended, reason)."""
    fn = filename.lower()
    rel_lower = rel_path.lower().replace("\\", "/")
    ext = os.path.splitext(fn)[1].lower()

    # ----------------------------------------------------------------
    # Nemo (M5Stick Nemo)
    # ----------------------------------------------------------------
    if "nemo" in rel_lower or fn.startswith("nemo"):
        if ext in (".pcap", ".pcapng"):
            return "nemo", "pcap_capture", True, "Nemo capture"
        if ext in (".txt", ".log", ".csv", ".json", ".html"):
            rec = "creds" in fn or "loot" in rel_lower
            return "nemo", "nemo_output", rec, "Nemo output/results"

    # ----------------------------------------------------------------
    # Bruce
    # ----------------------------------------------------------------
    if fn in _BRUCE_FILES_RECOMMENDED:
        return "bruce", "bruce_creds", True, "Bruce creds/results"
    if fn in _BRUCE_FILES_OPTIONAL:
        return "bruce", "bruce_config", False, "Bruce config/customization"
    if "/scripts/" in rel_lower:
        return "bruce", "bruce_script", False, "Bruce scripts"

    # ----------------------------------------------------------------
    # Hashcat .22000 (from any tool — Jammit, Porkchop, manual)
    # ----------------------------------------------------------------
    if ext == ".22000":
        return "marauder", "handshake_22000", True, "Hashcat 22000 handshake"

    # ----------------------------------------------------------------
    # Porkchop loot directory
    # ----------------------------------------------------------------
    if "porkchop" in rel_lower or "/loot/" in rel_lower or rel_lower.endswith("/loot"):
        if ext in (".pcap", ".pcapng"):
            return "porkchop", "pcap_capture", True, "Porkchop loot capture"
        if ext in (".txt", ".log", ".csv", ".json"):
            return "porkchop", "loot_meta", False, "Porkchop loot metadata"

    # ----------------------------------------------------------------
    # Jammit per-target capture directories: captures/<SSID_BSSID>/
    # These contain bare-named files (beacon.pcap, handshakes.pcap, etc.)
    # ----------------------------------------------------------------
    if _in_jammit_capture_dir(rel_lower):
        if ext in (".pcap", ".pcapng"):
            if fn in _JAMMIT_PCAP_NAMES:
                kind_tag = os.path.splitext(fn)[0]  # beacon, handshakes, raw, jammit_deauths
                return "marauder", f"pcap_{kind_tag}", True, f"Jammit {fn}"
            # Named handshake pcaps inside Handshakes/ subdir: SSID_BSSID_N.pcap
            if "/handshakes/" in rel_lower:
                return "marauder", "pcap_handshakes", True, "Jammit named handshake PCAP"
            return "marauder", "pcap_jammit", True, "Jammit capture"
        if fn == "capture_summary.txt":
            return "marauder", "jammit_summary", True, "Jammit capture summary"
        if fn == "stats.csv":
            return "marauder", "jammit_stats", True, "Jammit per-second stats"
        if fn in ("jammit_session.log",):
            return "marauder", "jammit_session", False, "Jammit session log (metadata)"
        if ext in (".log", ".txt"):
            return "marauder", "jammit_other", False, "Jammit session file"
        if ext == ".csv":
            for p in _MARAUDER_CSV_PREFIXES:
                if fn.startswith(p):
                    return "marauder", "log_" + p.rstrip("_"), True, "Marauder scan CSV"
            return "marauder", "jammit_other", False, "Jammit CSV file"
        return "marauder", "jammit_other", False, "Jammit session file"

    # ----------------------------------------------------------------
    # Marauder — PCAP files
    # ----------------------------------------------------------------
    if ext in (".pcap", ".pcapng"):
        for p in _MARAUDER_PCAP_PREFIXES:
            if fn.startswith(p):
                return "marauder", "pcap_" + p.rstrip("_"), True, "Marauder capture"
        return "unknown", "pcap", False, "PCAP (unrecognized naming)"

    # ----------------------------------------------------------------
    # Marauder — CSV scan outputs (portscan_*.csv, recon_scan.csv, etc.)
    # ----------------------------------------------------------------
    if ext == ".csv":
        for p in _MARAUDER_CSV_PREFIXES:
            if fn.startswith(p):
                return "marauder", "recon_csv", True, "Marauder scan result (CSV)"
        return "unknown", "other", False, "CSV (unrecognized)"

    # ----------------------------------------------------------------
    # Marauder — log / text outputs
    # ----------------------------------------------------------------
    if ext in (".log", ".txt"):
        for p in _MARAUDER_LOG_PREFIXES:
            if fn.startswith(p):
                kind = "log_" + p.rstrip("_").rstrip("_wardrive").rstrip("_")
                # Preserve full prefix for wardrive variants so analysis picks them up
                kind = "log_" + p.rstrip("_")
                return "marauder", kind, True, "Marauder output log"
        return "unknown", "log", False, "Log/text (unrecognized naming)"

    # ----------------------------------------------------------------
    # Firmware / other
    # ----------------------------------------------------------------
    if ext in (".bin", ".uf2"):
        return "unknown", "firmware", False, "Firmware/update"
    if ext == ".json":
        return "unknown", "other", False, "JSON config/data"
    return "unknown", "other", False, "Not recognized"


def is_output_artifact_filename(filename: str) -> bool:
    return filename.lower() in _PROJECT_OUTPUT_FILENAMES


def scan_sd_folder(sd_root: str, include_hidden: bool = False) -> List[CandidateFile]:
    """Scan SD folder and return candidates (unknowns included, but not auto-selected)."""
    results: List[CandidateFile] = []
    sd_root = os.path.abspath(sd_root)

    for dirpath, dirnames, filenames in os.walk(sd_root, onerror=lambda _: None):
        # Filter directories in-place: skip project output dirs and protected system folders
        filtered = []
        for d in dirnames:
            full = os.path.join(dirpath, d)
            # Skip Windows system folders that cause permission hangs
            if d in ("System Volume Information", "$RECYCLE.BIN", "$SysReset",
                     "System Recovery", "Recovery", "RECYCLER"):
                continue
            if should_skip_dir(full):
                continue
            filtered.append(d)
        dirnames[:] = filtered

        for fn in filenames:
            if not include_hidden and fn.startswith("."):
                continue
            if is_output_artifact_filename(fn):
                continue

            abs_path = os.path.join(dirpath, fn)
            try:
                st = os.stat(abs_path)
            except OSError:
                continue

            rel_path = os.path.relpath(abs_path, sd_root).replace("\\", "/")
            ext = os.path.splitext(fn)[1].lower()
            app, kind, rec, reason = classify_candidate(rel_path, fn)
            results.append(
                CandidateFile(
                    abs_path=abs_path,
                    rel_path=rel_path,
                    filename=fn,
                    ext=ext,
                    source_app=app,
                    kind=kind,
                    recommended=rec,
                    reason=reason,
                    size=int(st.st_size),
                )
            )

    results.sort(key=lambda c: (c.source_app, c.kind, c.rel_path))
    return results


_FILE_PROGRESS_MIN_BYTES = 1 * 1024 * 1024  # only emit byte progress for files >= 1 MB


def ingest_candidates_to_project(
    project_dir: str,
    sd_root: str,
    candidates: List[CandidateFile],
    label: str = "",
    skip_duplicates: bool = True,
    progress_cb=None,
    file_progress_cb=None,
) -> Dict[str, int]:
    """
    Copy-ingest candidates into the project vault. Dedupe is SHA-256 content-based.

    file_progress_cb(filename, phase, bytes_done, bytes_total)
        phase: "hash" | "copy"
        Called each chunk for files >= _FILE_PROGRESS_MIN_BYTES.
    """
    db_path = ensure_project_vault(project_dir)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    stats = {"total": len(candidates), "imported": 0, "duplicates": 0, "errors": 0}

    try:
        c = conn.cursor()
        created_utc = datetime.now(timezone.utc).isoformat(timespec="seconds")
        c.execute(
            "INSERT INTO imports(created_utc, source_path, label) VALUES(?,?,?)",
            (created_utc, sd_root, label),
        )
        import_id = c.lastrowid
        conn.commit()

        import_folder_name = datetime.now().strftime("%Y-%m-%d_%H%M%S") + (f"_{label}" if label else "_Import")
        dest_root = os.path.join(project_dir, "evidence", "imports", import_folder_name)
        os.makedirs(dest_root, exist_ok=True)

        c.execute("SELECT sha256, stored_path FROM evidence_files GROUP BY sha256")
        existing = {row[0]: row[1] for row in c.fetchall()}

        for idx, cand in enumerate(candidates, start=1):
            if progress_cb:
                progress_cb(f"Ingest {idx}/{len(candidates)}: hashing {cand.filename} ...")

            large = cand.size >= _FILE_PROGRESS_MIN_BYTES

            def _hash_cb(done, total, _fn=cand.filename):
                if file_progress_cb:
                    file_progress_cb(_fn, "hash", done, total)

            try:
                h = sha256_file(cand.abs_path, progress_cb=(_hash_cb if large else None))
            except Exception as e:
                stats["errors"] += 1
                if progress_cb:
                    progress_cb(f"ERROR hashing {cand.rel_path}: {e}")
                continue

            is_dup = h in existing
            if is_dup and skip_duplicates:
                stored_path = existing[h]
                stats["duplicates"] += 1
                if progress_cb:
                    progress_cb(f"Duplicate (hash match) skipped copy: {cand.rel_path}")
            else:
                dest_path = os.path.join(dest_root, cand.rel_path)
                os.makedirs(os.path.dirname(dest_path), exist_ok=True)

                def _copy_cb(done, total, _fn=cand.filename):
                    if file_progress_cb:
                        file_progress_cb(_fn, "copy", done, total)

                try:
                    _copy_with_progress(cand.abs_path, dest_path,
                                        progress_cb=(_copy_cb if large else None))
                except Exception as e:
                    stats["errors"] += 1
                    if progress_cb:
                        progress_cb(f"ERROR copying {cand.rel_path}: {e}")
                    continue
                stored_path = dest_path
                existing[h] = stored_path
                stats["imported"] += 1
                if progress_cb:
                    progress_cb(f"Copied: {cand.rel_path}")

            try:
                st = os.stat(cand.abs_path)
                c.execute(
                    "INSERT INTO evidence_files("
                    "import_id, original_path, stored_path, rel_path, sha256, size, mtime_ns, "
                    "source_app, kind, recommended, is_duplicate"
                    ") VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        import_id,
                        cand.abs_path,
                        stored_path,
                        cand.rel_path,
                        h,
                        int(st.st_size),
                        int(st.st_mtime_ns),
                        cand.source_app,
                        cand.kind,
                        1 if cand.recommended else 0,
                        1 if is_dup else 0,
                    ),
                )
                conn.commit()
            except Exception as e:
                stats["errors"] += 1
                if progress_cb:
                    progress_cb(f"ERROR recording DB for {cand.rel_path}: {e}")

    finally:
        conn.close()

    return stats

# -----------------------------
# Project evidence helpers
# -----------------------------
def list_project_evidence(project_dir: str) -> List[Dict[str, str]]:
    """Return all evidence rows for the project (stored_path, rel_path, kind, source_app, sha256)."""
    db_path = ensure_project_vault(project_dir)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        c = conn.cursor()
        c.execute(
            "SELECT stored_path, rel_path, kind, source_app, sha256, size "
            "FROM evidence_files "
            "ORDER BY rel_path"
        )
        return [dict(r) for r in c.fetchall()]
    finally:
        conn.close()


def gather_project_inputs_for_analysis(project_dir: str) -> Tuple[List[str], List[str]]:
    """Build (wardrive_logs, pcaps) from project vault evidence.

    Only WiGLE-format wardrive logs are included as logs; session/debug/scan
    outputs are excluded even if their kind starts with 'log_'.
    """
    rows = list_project_evidence(project_dir)
    logs: List[str] = []
    pcaps: List[str] = []
    for r in rows:
        p = r.get("stored_path") or ""
        if not p or not os.path.exists(p):
            continue
        kind = (r.get("kind") or "").lower()
        ext = os.path.splitext(p)[1].lower()

        if ext in (".pcap", ".pcapng") or kind.startswith("pcap_"):
            pcaps.append(p)
        elif ext in (".log", ".txt") and kind not in _NON_WARDRIVE_LOG_KINDS:
            # Only accept WiGLE-format text log extensions; .csv is never a wardrive log
            logs.append(p)

    logs = sorted(dict.fromkeys(logs))
    pcaps = sorted(dict.fromkeys(pcaps))
    return logs, pcaps


# ---------------------------------------------------------------------------
# Wigle CSV export
# ---------------------------------------------------------------------------

def export_wigle_csv(master_csv_path: str, out_path: str) -> int:
    """
    Convert a wardrive_master.csv into a WiGLE-compatible upload CSV.
    Returns number of rows written.

    WiGLE upload format (v1.4 header):
      WigleWifi-1.4,appRelease=WardriveAnalyzer,...
      MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type
    """
    if not os.path.exists(master_csv_path):
        return 0

    wigle_rows = []
    with open(master_csv_path, "r", newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            mac = row.get("MAC") or row.get("BSSID") or ""
            if not mac:
                continue
            wigle_rows.append({
                "MAC": mac,
                "SSID": row.get("TopSSID", ""),
                "AuthMode": row.get("AuthMode", ""),
                "FirstSeen": "",
                "Channel": row.get("Channel", ""),
                "RSSI": row.get("BestRSSI", ""),
                "CurrentLatitude": row.get("CentroidLat", ""),
                "CurrentLongitude": row.get("CentroidLon", ""),
                "AltitudeMeters": "",
                "AccuracyMeters": row.get("ConfidenceRadiusM", ""),
                "Type": "WIFI",
            })

    if not wigle_rows:
        return 0

    os.makedirs(os.path.dirname(out_path) if os.path.dirname(out_path) else ".", exist_ok=True)
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        f.write("WigleWifi-1.4,appRelease=WardriveAnalyzer,model=WardriveAnalyzer,release=4A\n")
        writer = csv.DictWriter(f, fieldnames=list(wigle_rows[0].keys()))
        writer.writeheader()
        writer.writerows(wigle_rows)
    return len(wigle_rows)


# ---------------------------------------------------------------------------
# WPA-sec handshake export
# ---------------------------------------------------------------------------

def export_wpasec_list(project_dir: str, out_path: str) -> int:
    """
    Produce a manifest of PCAP files that contain EAPOL handshake evidence,
    for manual or automated WPA-sec upload.
    Returns number of files listed.
    """
    rows = list_project_evidence(project_dir)
    pcap_paths = [
        r.get("stored_path", "")
        for r in rows
        if os.path.splitext(r.get("stored_path", ""))[1].lower() in (".pcap", ".pcapng")
        and os.path.exists(r.get("stored_path", ""))
    ]
    if not pcap_paths:
        return 0

    os.makedirs(os.path.dirname(out_path) if os.path.dirname(out_path) else ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("# WPA-sec upload manifest — generated by Wardrive Analyzer\n")
        f.write("# Upload each file at https://wpa-sec.stanev.org/\n\n")
        for p in sorted(pcap_paths):
            f.write(p + "\n")
    return len(pcap_paths)
