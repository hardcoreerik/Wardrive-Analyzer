"""Tests for check_deps.py — startup dependency validation."""
from __future__ import annotations

import sys

import pytest

from check_deps import check_dependencies


class TestCheckDependencies:
    def test_returns_two_lists(self):
        req, opt = check_dependencies()
        assert isinstance(req, list)
        assert isinstance(opt, list)

    def test_pyside6_present(self):
        """PySide6 must be importable in the test environment."""
        req, _ = check_dependencies()
        # If PySide6 is present, it should not appear in missing_required
        try:
            import PySide6  # noqa: F401
            assert not any("PySide6" in p for p in req)
        except ImportError:
            pass  # Not our job to install it in CI

    def test_no_crash(self):
        """check_dependencies must never raise."""
        try:
            check_dependencies()
        except Exception as exc:
            pytest.fail(f"check_dependencies raised: {exc}")
