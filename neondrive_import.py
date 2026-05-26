"""
neondrive_import.py — Import NEONDRIVE session bundles into the Wardrive Analyzer project vault.

Workflow:
  1. NEONDRIVE firmware stages a session bundle on SD card.
  2. Firmware uploads the bundle to Dropbox.
  3. Dropbox desktop app syncs to PC under the configured path.
  4. Technician clicks "Import NEONDRIVE Session" in Wardrive Analyzer.
  5. This module validates the bundle, reads the manifest, and ingests
     evidence files into the project vault with SHA-256 deduplication.

Bundle structure expected at <session_dir>/:
  manifest.json           (required — neondrive.session.v1 schema)
  sync_complete.flag      (required — upload atomicity marker)
  summary.json            (optional)
  events.csv              (optional)
  artifacts/              (optional — PCAPs, .22000, stats.csv)
  logs/                   (optional — capture_summary.txt, jammit_session.log)
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional


SUPPORTED_SCHEMAS = {"neondrive.session.v1"}

# Files that are evidence artifacts worth ingesting
_INGEST_EXTENSIONS = {".pcap", ".pcapng", ".22000", ".hc22000", ".csv", ".log", ".txt", ".json"}
# Files that must NOT be ingested (security: never execute these)
_BLOCKED_EXTENSIONS = {".exe", ".bat", ".sh", ".py", ".js", ".bin", ".elf"}
# Metadata files — ingest but mark not-recommended
_META_FILENAMES = {"manifest.json", "summary.json", "sync_complete.flag", "events.csv"}


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class NeondriveManifest:
    schema: str
    session_id: str
    device_id: str
    hardware: str
    module: str
    ssid: str
    bssid: str
    channel: int
    security: str
    quick_status: str
    findings: List[Dict]
    artifacts: List[Dict]
    millis_since_boot: int


@dataclass
class ImportResult:
    ok: bool
    session_id: str = ""
    status: str = ""       # "imported" | "already_imported" | "incomplete" | "invalid_manifest" | "missing_required" | "error"
    message: str = ""
    files_imported: int = 0
    files_skipped: int = 0
    errors: List[str] = field(default_factory=list)


# ── Validation ────────────────────────────────────────────────────────────────

def _safe_rel_path(base: str, rel: str) -> Optional[str]:
    """Resolve rel relative to base and reject path traversal. Returns abs path or None."""
    abs_path = os.path.normpath(os.path.join(base, rel))
    if not abs_path.startswith(os.path.normpath(base) + os.sep):
        return None
    return abs_path


def validate_neondrive_session(session_dir: str) -> tuple[bool, str]:
    """
    Check that session_dir contains a complete NEONDRIVE session bundle.

    Returns (ok, reason). ok=True means the bundle is safe to import.
    Checks:
      - sync_complete.flag exists (atomicity guard)
      - manifest.json exists and parses as valid JSON
      - manifest schema is supported
      - session_id is present and non-empty
    """
    session_dir = os.path.abspath(session_dir)

    flag_path = os.path.join(session_dir, "sync_complete.flag")
    if not os.path.exists(flag_path):
        return False, "incomplete: sync_complete.flag not present (upload may still be in progress)"

    manifest_path = os.path.join(session_dir, "manifest.json")
    if not os.path.exists(manifest_path):
        return False, "missing_required: manifest.json not found"

    try:
        with open(manifest_path, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        return False, f"invalid_manifest: {e}"

    schema = data.get("schema", "")
    if schema not in SUPPORTED_SCHEMAS:
        return False, f"invalid_manifest: unsupported schema '{schema}' (supported: {SUPPORTED_SCHEMAS})"

    session_id = data.get("session_id", "").strip()
    if not session_id:
        return False, "invalid_manifest: session_id is missing or empty"

    # Reject obviously bad session_ids
    if ".." in session_id or "/" in session_id or "\\" in session_id:
        return False, "invalid_manifest: session_id contains illegal characters"

    return True, "ok"


def parse_neondrive_manifest(session_dir: str) -> Optional[NeondriveManifest]:
    """Parse manifest.json and return a NeondriveManifest, or None on failure."""
    manifest_path = os.path.join(session_dir, "manifest.json")
    try:
        with open(manifest_path, encoding="utf-8") as f:
            d = json.load(f)
    except (json.JSONDecodeError, OSError):
        return None

    device = d.get("device", {})
    profile = d.get("profile", {})
    target = d.get("target", {})
    timing = d.get("timing", {})
    result = d.get("quick_result", {})

    return NeondriveManifest(
        schema=d.get("schema", ""),
        session_id=d.get("session_id", ""),
        device_id=device.get("device_id", ""),
        hardware=device.get("hardware", ""),
        module=profile.get("module", ""),
        ssid=target.get("ssid", ""),
        bssid=target.get("bssid", ""),
        channel=int(target.get("channel", 0)),
        security=target.get("security", ""),
        quick_status=result.get("status", "INCONCLUSIVE"),
        findings=result.get("findings", []),
        artifacts=d.get("artifacts", []),
        millis_since_boot=int(timing.get("millis_since_boot", 0)),
    )


# ── Import ────────────────────────────────────────────────────────────────────

def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def import_neondrive_session(
    project_dir: str,
    session_dir: str,
    progress_cb: Optional[Callable[[str], None]] = None,
) -> ImportResult:
    """
    Import a NEONDRIVE session bundle into the Wardrive Analyzer project vault.

    Args:
        project_dir:  Path to the Wardrive Analyzer project directory.
        session_dir:  Path to the local NEONDRIVE session folder
                      (e.g., the Dropbox-synced /neondrive/sessions/ND-…/ folder).
        progress_cb:  Optional callback(message: str) for progress updates.

    Returns:
        ImportResult with status and counts.
    """
    from project_vault import ensure_project_vault, sha256_exists, DB_NAME

    def log(msg: str) -> None:
        if progress_cb:
            progress_cb(msg)

    session_dir = os.path.abspath(session_dir)
    project_dir = os.path.abspath(project_dir)

    # ── 1. Validate ───────────────────────────────────────────────────────────
    ok, reason = validate_neondrive_session(session_dir)
    if not ok:
        status = reason.split(":")[0]
        return ImportResult(ok=False, status=status, message=reason)

    manifest = parse_neondrive_manifest(session_dir)
    if manifest is None:
        return ImportResult(ok=False, status="invalid_manifest", message="Failed to parse manifest.json")

    log(f"Importing NEONDRIVE session: {manifest.session_id}")
    log(f"  Device: {manifest.device_id}  Module: {manifest.module}  Target: {manifest.ssid}")

    # ── 2. Ensure vault DB exists ─────────────────────────────────────────────
    ensure_project_vault(project_dir)

    import sqlite3
    db_path = os.path.join(project_dir, DB_NAME)

    with sqlite3.connect(db_path) as conn:
        # ── 3. Idempotency check — have we seen this session_id before? ───────
        cur = conn.cursor()
        cur.execute("SELECT id FROM imports WHERE label = ?", (manifest.session_id,))
        existing = cur.fetchone()
        if existing:
            log(f"Session {manifest.session_id} already imported (import #{existing[0]}). Skipping.")
            return ImportResult(
                ok=True,
                session_id=manifest.session_id,
                status="already_imported",
                message=f"Session {manifest.session_id} was previously imported.",
            )

        # ── 4. Register import record ─────────────────────────────────────────
        cur.execute(
            "INSERT INTO imports (created_utc, source_path, label) VALUES (datetime('now'), ?, ?)",
            (session_dir, manifest.session_id),
        )
        import_id = cur.lastrowid
        conn.commit()

    # ── 5. Create evidence destination directory ───────────────────────────────
    import_label = f"{manifest.session_id}"
    from datetime import datetime, timezone
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
    dest_dir = os.path.join(project_dir, "evidence", "imports", f"{ts}_{import_label}")
    os.makedirs(dest_dir, exist_ok=True)

    # ── 6. Walk the session dir and ingest files ───────────────────────────────
    result = ImportResult(ok=True, session_id=manifest.session_id, status="imported")

    with sqlite3.connect(db_path) as conn:
        cur = conn.cursor()

        for dirpath, _dirs, filenames in os.walk(session_dir):
            for filename in filenames:
                abs_src = os.path.join(dirpath, filename)
                rel_path = os.path.relpath(abs_src, session_dir).replace("\\", "/")
                ext = os.path.splitext(filename)[1].lower()

                # Reject blocked extensions (security: never execute)
                if ext in _BLOCKED_EXTENSIONS:
                    log(f"  SKIP (blocked ext): {rel_path}")
                    result.files_skipped += 1
                    continue

                # Reject path traversal in artifact paths from manifest
                safe_dest = _safe_rel_path(dest_dir, rel_path)
                if safe_dest is None:
                    log(f"  SKIP (path traversal): {rel_path}")
                    result.errors.append(f"Path traversal rejected: {rel_path}")
                    result.files_skipped += 1
                    continue

                # Skip zero-byte files (sync_complete.flag is intentionally tiny, but keep it)
                try:
                    size = os.path.getsize(abs_src)
                except OSError:
                    continue

                # SHA-256 dedup check
                try:
                    sha = _sha256_file(abs_src)
                except OSError as e:
                    log(f"  SKIP (read error): {rel_path} — {e}")
                    result.errors.append(str(e))
                    result.files_skipped += 1
                    continue

                with sqlite3.connect(db_path) as conn2:
                    cur2 = conn2.cursor()
                    cur2.execute("SELECT id FROM evidence_files WHERE sha256 = ?", (sha,))
                    dup = cur2.fetchone()
                    is_duplicate = dup is not None

                # Determine kind and recommended flag
                is_meta = filename in _META_FILENAMES
                recommended: bool
                kind: str
                if filename == "sync_complete.flag":
                    kind, recommended = "neondrive_flag", False
                elif filename == "manifest.json":
                    kind, recommended = "neondrive_meta", False
                elif filename == "summary.json":
                    kind, recommended = "neondrive_meta", False
                elif filename == "events.csv":
                    kind, recommended = "neondrive_events", True
                elif ext in (".pcap", ".pcapng"):
                    kind, recommended = "pcap_neondrive", True
                elif ext in (".22000", ".hc22000") or filename.endswith(".hc22000"):
                    kind, recommended = "handshake_22000", True
                elif filename == "stats.csv":
                    kind, recommended = "neondrive_session_log", False
                else:
                    kind, recommended = "neondrive_other", False

                # Copy file to evidence dir
                os.makedirs(os.path.dirname(safe_dest), exist_ok=True)
                try:
                    shutil.copy2(abs_src, safe_dest)
                except OSError as e:
                    log(f"  ERROR copying {rel_path}: {e}")
                    result.errors.append(str(e))
                    continue

                # Insert evidence record
                mtime_ns = int(os.stat(abs_src).st_mtime_ns) if hasattr(os.stat(abs_src), "st_mtime_ns") else 0
                with sqlite3.connect(db_path) as conn3:
                    cur3 = conn3.cursor()
                    cur3.execute(
                        """INSERT INTO evidence_files
                           (import_id, original_path, stored_path, rel_path, sha256,
                            size, mtime_ns, source_app, kind, recommended, is_duplicate)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                        (
                            import_id,
                            abs_src,
                            safe_dest,
                            rel_path,
                            sha,
                            size,
                            mtime_ns,
                            "neondrive",
                            kind,
                            1 if recommended else 0,
                            1 if is_duplicate else 0,
                        ),
                    )
                    conn3.commit()

                status_tag = "[DUP]" if is_duplicate else "[OK] "
                log(f"  {status_tag} {rel_path} ({size:,} bytes)")
                result.files_imported += 1

    result.message = (
        f"Imported {result.files_imported} file(s) from session {manifest.session_id}. "
        f"Module: {manifest.module}. Quick result: {manifest.quick_status}."
    )
    if result.errors:
        result.message += f" {len(result.errors)} error(s) — see result.errors."

    log(f"Import complete: {result.message}")
    return result
