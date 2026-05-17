"""Shared pytest fixtures for Wardrive Analyzer tests."""
from __future__ import annotations

import os
import sys
import tempfile

import pytest

# Ensure repo root is importable without requiring pip install
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


@pytest.fixture()
def sample_csv() -> str:
    return os.path.join(FIXTURES_DIR, "sample_wardrive.csv")


@pytest.fixture()
def malformed_csv() -> str:
    return os.path.join(FIXTURES_DIR, "malformed.csv")


@pytest.fixture()
def empty_csv() -> str:
    return os.path.join(FIXTURES_DIR, "empty.csv")


@pytest.fixture()
def wigle_csv() -> str:
    return os.path.join(FIXTURES_DIR, "wigle_export.csv")


@pytest.fixture()
def beacon_pcap() -> str:
    return os.path.join(FIXTURES_DIR, "beacon.pcap")


@pytest.fixture()
def probe_pcap() -> str:
    return os.path.join(FIXTURES_DIR, "probe_resp.pcap")


@pytest.fixture()
def corrupted_pcap() -> str:
    return os.path.join(FIXTURES_DIR, "corrupted.pcap")


@pytest.fixture()
def empty_pcap() -> str:
    return os.path.join(FIXTURES_DIR, "empty.pcap")


@pytest.fixture()
def tmp_project(tmp_path) -> str:
    """Return a temporary project directory with a valid vault."""
    project_dir = str(tmp_path / "test_project")
    os.makedirs(project_dir, exist_ok=True)
    return project_dir
