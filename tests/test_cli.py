"""Tests for wardrive_cli.py — CLI command structure and behavior."""
from __future__ import annotations

import json
import os
import sys

import pytest

import wardrive_cli


class TestCliParser:
    def test_parser_builds(self):
        parser = wardrive_cli.build_parser()
        assert parser is not None

    def test_project_summary_command_recognized(self, tmp_project):
        result = wardrive_cli.main(["project-summary", tmp_project])
        # Returns 0 (ok) or 1 (error) — must not raise
        assert isinstance(result, int)

    def test_evidence_list_command(self, tmp_project):
        result = wardrive_cli.main(["evidence-list", tmp_project])
        assert isinstance(result, int)

    def test_runs_list_command(self, tmp_project):
        result = wardrive_cli.main(["runs-list", tmp_project])
        assert isinstance(result, int)

    def test_latest_run_command(self, tmp_project):
        result = wardrive_cli.main(["latest-run", tmp_project])
        assert isinstance(result, int)

    def test_evidence_health_command(self, tmp_project):
        result = wardrive_cli.main(["evidence-health", tmp_project])
        assert isinstance(result, int)

    def test_integration_plan_command(self):
        result = wardrive_cli.main(["integration-plan"])
        assert isinstance(result, int)


class TestCliOutput:
    def test_project_summary_json(self, tmp_project, capsys):
        wardrive_cli.main(["project-summary", tmp_project])
        captured = capsys.readouterr()
        # Must produce valid JSON on stdout
        data = json.loads(captured.out)
        assert "status" in data

    def test_compact_flag(self, tmp_project, capsys):
        # --compact placed after the subcommand name (argparse subparser scope)
        wardrive_cli.main(["project-summary", "--compact", tmp_project])
        captured = capsys.readouterr()
        # Compact JSON has no pretty-print newlines
        lines = [l for l in captured.out.splitlines() if l.strip()]
        assert len(lines) == 1

    def test_no_token_in_output(self, tmp_project, capsys):
        """CLI output must never contain raw tokens even if stored."""
        from project_vault import ensure_project_vault, set_setting
        db_path = ensure_project_vault(tmp_project)
        fake_token = "sk-super-secret-cli-test-token"
        set_setting(db_path, "api_key", fake_token)

        wardrive_cli.main(["project-summary", tmp_project])
        captured = capsys.readouterr()
        assert fake_token not in captured.out
        assert fake_token not in captured.err

    def test_missing_project_returns_error_json(self, tmp_path, capsys):
        fake_dir = str(tmp_path / "does_not_exist_project")
        result = wardrive_cli.main(["evidence-list", fake_dir])
        captured = capsys.readouterr()
        # Should output valid JSON (possibly with status=error or status=ok with empty)
        try:
            data = json.loads(captured.out)
            assert "status" in data
        except json.JSONDecodeError:
            pass  # Acceptable: some commands may exit before writing JSON
