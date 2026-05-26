"""Tests for NEONDRIVE session bundle validation and import."""
from __future__ import annotations

import json
import os
import shutil
import sqlite3

import pytest

from neondrive_import import (
    ImportResult,
    NeondriveManifest,
    import_neondrive_session,
    parse_neondrive_manifest,
    validate_neondrive_session,
)
from project_vault import classify_candidate, ensure_project_vault

# ── Fixture paths ─────────────────────────────────────────────────────────────

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "neondrive_session_v1")


@pytest.fixture()
def valid_session(tmp_path) -> str:
    """Copy the fixture session to a temp dir and return its path."""
    dest = str(tmp_path / "neondrive_session_v1")
    shutil.copytree(FIXTURE_DIR, dest)
    return dest


@pytest.fixture()
def incomplete_session(tmp_path) -> str:
    """Session folder without sync_complete.flag."""
    dest = str(tmp_path / "incomplete_session")
    shutil.copytree(FIXTURE_DIR, dest)
    flag = os.path.join(dest, "sync_complete.flag")
    os.remove(flag)
    return dest


@pytest.fixture()
def bad_manifest_session(tmp_path) -> str:
    """Session folder with invalid JSON in manifest.json."""
    dest = str(tmp_path / "bad_manifest")
    shutil.copytree(FIXTURE_DIR, dest)
    with open(os.path.join(dest, "manifest.json"), "w") as f:
        f.write("not valid json {{{")
    return dest


@pytest.fixture()
def wrong_schema_session(tmp_path) -> str:
    """Session folder with unsupported schema in manifest."""
    dest = str(tmp_path / "wrong_schema")
    shutil.copytree(FIXTURE_DIR, dest)
    manifest_path = os.path.join(dest, "manifest.json")
    with open(manifest_path) as f:
        data = json.load(f)
    data["schema"] = "neondrive.session.v99"
    with open(manifest_path, "w") as f:
        json.dump(data, f)
    return dest


@pytest.fixture()
def project(tmp_path) -> str:
    """Empty project directory with vault initialized."""
    p = str(tmp_path / "project")
    os.makedirs(p)
    ensure_project_vault(p)
    return p


# ── validate_neondrive_session tests ─────────────────────────────────────────

class TestValidateSession:
    def test_valid_session_passes(self, valid_session):
        ok, reason = validate_neondrive_session(valid_session)
        assert ok is True
        assert reason == "ok"

    def test_incomplete_session_rejected(self, incomplete_session):
        ok, reason = validate_neondrive_session(incomplete_session)
        assert ok is False
        assert "sync_complete.flag" in reason
        assert "incomplete" in reason

    def test_missing_manifest_rejected(self, tmp_path):
        d = str(tmp_path / "no_manifest")
        os.makedirs(d)
        open(os.path.join(d, "sync_complete.flag"), "w").close()
        ok, reason = validate_neondrive_session(d)
        assert ok is False
        assert "manifest.json" in reason

    def test_invalid_json_rejected(self, bad_manifest_session):
        ok, reason = validate_neondrive_session(bad_manifest_session)
        assert ok is False
        assert "invalid_manifest" in reason

    def test_wrong_schema_rejected(self, wrong_schema_session):
        ok, reason = validate_neondrive_session(wrong_schema_session)
        assert ok is False
        assert "unsupported schema" in reason

    def test_path_traversal_in_session_id_rejected(self, tmp_path):
        d = str(tmp_path / "traversal")
        os.makedirs(d)
        open(os.path.join(d, "sync_complete.flag"), "w").close()
        bad_manifest = {
            "schema": "neondrive.session.v1",
            "session_id": "../../etc/passwd",
            "device": {}, "profile": {}, "target": {}, "timing": {},
            "artifacts": [], "quick_result": {}
        }
        with open(os.path.join(d, "manifest.json"), "w") as f:
            json.dump(bad_manifest, f)
        ok, reason = validate_neondrive_session(d)
        assert ok is False
        assert "illegal" in reason


# ── parse_neondrive_manifest tests ────────────────────────────────────────────

class TestParseManifest:
    def test_parse_valid_manifest(self, valid_session):
        m = parse_neondrive_manifest(valid_session)
        assert m is not None
        assert m.session_id == "ND-CYD35-0001-SP3CTER-T0000300"
        assert m.device_id == "ND-CYD35-A91B58"
        assert m.module == "SP3CTER"
        assert m.ssid == "LabTestSSID"
        assert m.bssid == "AA:BB:CC:DD:EE:FF"
        assert m.channel == 6
        assert m.quick_status == "WARNING"
        assert len(m.findings) == 2

    def test_parse_returns_none_on_invalid(self, bad_manifest_session):
        m = parse_neondrive_manifest(bad_manifest_session)
        assert m is None


# ── import_neondrive_session tests ────────────────────────────────────────────

class TestImportSession:
    def test_valid_import_succeeds(self, valid_session, project):
        result = import_neondrive_session(project, valid_session)
        assert result.ok is True
        assert result.status == "imported"
        assert result.session_id == "ND-CYD35-0001-SP3CTER-T0000300"
        assert result.files_imported > 0

    def test_files_copied_to_evidence_dir(self, valid_session, project):
        import_neondrive_session(project, valid_session)
        evidence_root = os.path.join(project, "evidence", "imports")
        import_dirs = os.listdir(evidence_root)
        assert len(import_dirs) == 1
        files = []
        for dirpath, _, filenames in os.walk(os.path.join(evidence_root, import_dirs[0])):
            files.extend(filenames)
        assert "manifest.json" in files
        assert "events.csv" in files

    def test_import_is_idempotent(self, valid_session, project):
        r1 = import_neondrive_session(project, valid_session)
        r2 = import_neondrive_session(project, valid_session)
        assert r1.ok and r2.ok
        assert r1.status == "imported"
        assert r2.status == "already_imported"

    def test_incomplete_session_rejected(self, incomplete_session, project):
        result = import_neondrive_session(project, incomplete_session)
        assert result.ok is False
        assert "incomplete" in result.status

    def test_bad_manifest_rejected(self, bad_manifest_session, project):
        result = import_neondrive_session(project, bad_manifest_session)
        assert result.ok is False

    def test_source_app_recorded_as_neondrive(self, valid_session, project):
        import_neondrive_session(project, valid_session)
        db = os.path.join(project, "project.db")
        with sqlite3.connect(db) as conn:
            rows = conn.execute(
                "SELECT source_app FROM evidence_files WHERE source_app='neondrive'"
            ).fetchall()
        assert len(rows) > 0

    def test_hash_export_classified_correctly(self, valid_session, project):
        import_neondrive_session(project, valid_session)
        db = os.path.join(project, "project.db")
        with sqlite3.connect(db) as conn:
            rows = conn.execute(
                "SELECT kind FROM evidence_files WHERE kind='handshake_22000'"
            ).fetchall()
        assert len(rows) > 0

    def test_optional_artifact_missing_does_not_fail(self, valid_session, project):
        """Remove optional artifact; import should still succeed."""
        os.remove(os.path.join(valid_session, "artifacts", "stats.csv"))
        result = import_neondrive_session(project, valid_session)
        assert result.ok is True
        assert result.status == "imported"

    def test_progress_callback_called(self, valid_session, project):
        messages = []
        import_neondrive_session(project, valid_session, progress_cb=messages.append)
        assert len(messages) > 0
        assert any("ND-CYD35" in m for m in messages)


# ── classify_candidate tests for NEONDRIVE paths ─────────────────────────────

class TestClassifyCandidateNEONDRIVE:
    BASE = "neondrive/sessions/ND-CYD35-0001-SP3CTER-T0000300"

    def _classify(self, rel_suffix, filename):
        return classify_candidate(f"{self.BASE}/{rel_suffix}", filename)

    def test_manifest_classified_as_neondrive_meta(self):
        app, kind, rec, _ = self._classify("manifest.json", "manifest.json")
        assert app == "neondrive"
        assert kind == "neondrive_meta"
        assert rec is False

    def test_events_csv_classified_as_neondrive_events(self):
        app, kind, rec, _ = self._classify("events.csv", "events.csv")
        assert app == "neondrive"
        assert kind == "neondrive_events"
        assert rec is True

    def test_hc22000_classified_as_handshake(self):
        app, kind, rec, _ = self._classify("artifacts/specter.hc22000", "specter.hc22000")
        assert app == "neondrive"
        assert kind == "handshake_22000"
        assert rec is True

    def test_pcap_classified_as_neondrive_pcap(self):
        app, kind, rec, _ = self._classify("artifacts/handshakes.pcap", "handshakes.pcap")
        assert app == "neondrive"
        assert kind == "pcap_neondrive"
        assert rec is True

    def test_flag_classified_as_neondrive_meta(self):
        app, kind, rec, _ = self._classify("sync_complete.flag", "sync_complete.flag")
        assert app == "neondrive"
        assert kind == "neondrive_meta"
        assert rec is False

    def test_dropbox_incoming_path_also_matched(self):
        rel = "neondrive/incoming/ND-CYD35-A91B58/sessions/ND-CYD35-0001-SP3CTER-T0000300/manifest.json"
        app, kind, _, _ = classify_candidate(rel, "manifest.json")
        assert app == "neondrive"
