"""Tests for project_vault.py — project database creation and evidence tracking."""
from __future__ import annotations

import os
import sqlite3

import pytest

from project_vault import ensure_project_vault, get_setting, set_setting


class TestEnsureProjectVault:
    def test_creates_db(self, tmp_project):
        db_path = ensure_project_vault(tmp_project)
        assert os.path.exists(db_path)
        assert db_path.endswith(".db")

    def test_idempotent(self, tmp_project):
        """Calling ensure_project_vault twice must not raise."""
        db1 = ensure_project_vault(tmp_project)
        db2 = ensure_project_vault(tmp_project)
        assert db1 == db2

    def test_db_has_required_tables(self, tmp_project):
        db_path = ensure_project_vault(tmp_project)
        with sqlite3.connect(db_path) as conn:
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
        assert "settings" in tables

    def test_returns_string_path(self, tmp_project):
        db_path = ensure_project_vault(tmp_project)
        assert isinstance(db_path, str)


class TestSettings:
    """set_setting/get_setting take a DB FILE PATH (returned by ensure_project_vault)."""

    def test_set_and_get(self, tmp_project):
        db_path = ensure_project_vault(tmp_project)
        set_setting(db_path, "test_key", "test_value")
        result = get_setting(db_path, "test_key")
        assert result == "test_value"

    def test_get_missing_key_returns_default(self, tmp_project):
        db_path = ensure_project_vault(tmp_project)
        result = get_setting(db_path, "nonexistent_key", default="fallback")
        assert result == "fallback"

    def test_overwrite_setting(self, tmp_project):
        db_path = ensure_project_vault(tmp_project)
        set_setting(db_path, "k", "v1")
        set_setting(db_path, "k", "v2")
        assert get_setting(db_path, "k") == "v2"

    def test_token_not_stored_in_log(self, tmp_project, capfd):
        """Storing a token via set_setting must not print it to stdout/stderr."""
        db_path = ensure_project_vault(tmp_project)
        fake_token = "sk-super-secret-token-12345"
        set_setting(db_path, "api_token", fake_token)
        captured = capfd.readouterr()
        assert fake_token not in captured.out
        assert fake_token not in captured.err
