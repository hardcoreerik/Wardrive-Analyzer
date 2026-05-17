"""Tests for token redaction behavior in buddy_ai.py."""
from __future__ import annotations

import pytest

from buddy_ai import redact_token, _scrub, SECRET_KEY_PARTS


class TestRedactToken:
    def test_empty_token(self):
        assert redact_token("") == "[empty]"

    def test_whitespace_token(self):
        assert redact_token("   ") == "[empty]"

    def test_short_token(self):
        result = redact_token("abc")
        assert result == "[redacted]"

    def test_shows_hint_not_full_token(self):
        token = "sk-proj-abcdef1234567890xxxx"
        result = redact_token(token)
        assert token not in result
        assert "..." in result
        # Must show at most the last 4 chars and first 3
        assert result.endswith(token[-4:])
        assert result.startswith(token[:3])

    def test_never_exposes_middle(self):
        token = "sk-SUPERSECRETMIDDLEPART1234"
        result = redact_token(token)
        assert "SUPERSECRETMIDDLEPART" not in result


class TestScrubFunction:
    def test_secret_key_redacted(self):
        data = {"api_key": "my-secret-key-value"}
        result = _scrub(data)
        assert result["api_key"] == "[redacted]"

    def test_token_redacted(self):
        data = {"token": "abc123secret"}
        result = _scrub(data)
        assert result["token"] == "[redacted]"

    def test_password_redacted(self):
        data = {"password": "hunter2"}
        result = _scrub(data)
        assert result["password"] == "[redacted]"

    def test_credential_redacted(self):
        data = {"credential": "user:pass"}
        result = _scrub(data)
        assert result["credential"] == "[redacted]"

    def test_normal_value_passes(self):
        data = {"ssid": "SyntheticNet", "rssi": -65}
        result = _scrub(data)
        assert result["ssid"] == "SyntheticNet"
        assert result["rssi"] == -65

    def test_nested_secret_redacted(self):
        data = {"config": {"api_key": "secret-value"}}
        result = _scrub(data)
        assert result["config"]["api_key"] == "[redacted]"

    def test_path_value_redacted(self):
        data = {"file": "C:\\Users\\Victim\\Documents\\wardrive.csv"}
        result = _scrub(data)
        assert "C:\\Users\\Victim" not in str(result["file"])

    def test_list_values_scrubbed(self):
        # Note: key "keys" contains "key" substring so it matches SECRET_KEY_PARTS
        # and the whole value is redacted. Use a neutral key to test list processing.
        data = {"bssids": ["AA:BB:CC", "DD:EE:FF"]}
        result = _scrub(data)
        assert isinstance(result["bssids"], list)

    def test_none_safe(self):
        result = _scrub(None)
        assert result is None

    def test_no_token_in_output(self):
        """Comprehensive: build a context like buddy does and verify clean output."""
        context = {
            "status": "ok",
            "api_key": "sk-real-secret-key-12345678",
            "summary": {"total_aps": 10},
            "project_dir": "C:\\Users\\TestUser\\Projects\\myproject",
        }
        result = _scrub(context)
        output_str = str(result)
        assert "sk-real-secret-key-12345678" not in output_str
        assert "C:\\Users\\TestUser" not in output_str
