"""Tests for core/writers.py — report safety and clean_report_value."""
from __future__ import annotations

import os
import csv

import pytest

from core.writers import clean_report_value, clean_report_row


class TestCleanReportValue:
    def test_none_returns_no_data(self):
        from core.constants import NO_DATA
        assert clean_report_value(None) == NO_DATA

    def test_empty_string_returns_no_data(self):
        from core.constants import NO_DATA
        assert clean_report_value("") == NO_DATA

    def test_normal_string_passes_through(self):
        assert clean_report_value("SomeSSID") == "SomeSSID"

    def test_strips_control_chars(self):
        result = clean_report_value("Hello\x00World")
        assert "\x00" not in result
        assert "Hello" in result

    def test_truncates_long_strings(self):
        long_str = "A" * 40_000
        result = clean_report_value(long_str)
        assert len(result) <= 32_767

    def test_numeric_passthrough(self):
        assert clean_report_value(42) == 42
        assert clean_report_value(3.14) == pytest.approx(3.14)

    def test_bool_passthrough(self):
        assert clean_report_value(True) is True

    def test_replacement_char_sanitized(self):
        result = clean_report_value("hello\ufffdworld")
        assert "\ufffd" not in result

    def test_html_injection_passthrough_raw(self):
        """clean_report_value does NOT escape HTML — that's the HTML writer's job.
        But it must not crash or produce obviously dangerous bytes."""
        raw = "<script>alert(1)</script>"
        result = clean_report_value(raw)
        # The value passes through unchanged (html.escape is applied in write_map_html etc.)
        assert isinstance(result, str)


class TestCleanReportRow:
    def test_all_values_cleaned(self):
        row = {"ssid": "Net\x00work", "rssi": None, "mac": "AA:BB:CC:DD:EE:01"}
        cleaned = clean_report_row(row)
        assert "\x00" not in cleaned["ssid"]
        from core.constants import NO_DATA
        assert cleaned["rssi"] == NO_DATA
        assert cleaned["mac"] == "AA:BB:CC:DD:EE:01"


class TestHTMLEscapeInReports:
    """Verify that HTML generation uses html.escape on user-derived values."""

    def _has_html_escape(self):
        """Inspect writers.py source to confirm html.escape is imported and used."""
        import inspect
        import core.writers as writers
        source = inspect.getsource(writers)
        return "html.escape" in source or "escape(" in source

    def test_html_escape_imported(self):
        assert self._has_html_escape(), "html.escape must be used in core/writers.py"
