"""Tests for core/helpers.py."""
from __future__ import annotations

import math

import pytest

from core.helpers import norm_mac, safe_str, safe_float, safe_int, haversine_m, now_str


class TestNormMac:
    def test_uppercase(self):
        assert norm_mac("aa:bb:cc:dd:ee:ff") == "AA:BB:CC:DD:EE:FF"

    def test_already_upper(self):
        assert norm_mac("AA:BB:CC:DD:EE:FF") == "AA:BB:CC:DD:EE:FF"

    def test_strips_whitespace(self):
        assert norm_mac("  AA:BB:CC:DD:EE:FF  ") == "AA:BB:CC:DD:EE:FF"

    def test_empty(self):
        assert norm_mac("") == ""

    def test_none(self):
        assert norm_mac(None) == ""  # type: ignore[arg-type]


class TestSafeStr:
    def test_normal(self):
        assert safe_str("hello") == "hello"

    def test_empty_string(self):
        assert safe_str("") == "No Data"

    def test_none(self):
        assert safe_str(None) == "No Data"  # type: ignore[arg-type]


class TestSafeFloat:
    def test_valid(self):
        assert safe_float("3.14") == pytest.approx(3.14)

    def test_invalid(self):
        assert safe_float("not-a-number") is None

    def test_none(self):
        assert safe_float(None) is None  # type: ignore[arg-type]

    def test_empty(self):
        assert safe_float("") is None


class TestSafeInt:
    def test_valid(self):
        assert safe_int("42") == 42

    def test_float_string(self):
        assert safe_int("3.9") == 3

    def test_invalid(self):
        assert safe_int("abc") is None

    def test_none(self):
        assert safe_int(None) is None  # type: ignore[arg-type]


class TestHaversineM:
    def test_same_point(self):
        assert haversine_m(47.6, -122.3, 47.6, -122.3) == pytest.approx(0.0)

    def test_known_distance(self):
        # Seattle to Bellevue roughly ~10 km
        dist = haversine_m(47.6062, -122.3321, 47.6101, -122.2015)
        assert 8_000 < dist < 15_000

    def test_positive(self):
        assert haversine_m(0.0, 0.0, 1.0, 1.0) > 0


class TestNowStr:
    def test_returns_string(self):
        result = now_str()
        assert isinstance(result, str)
        assert len(result) >= 10
