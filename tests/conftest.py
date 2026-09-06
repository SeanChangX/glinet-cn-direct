"""Shared fixtures.

Tests never touch the network: upstream downloads are replaced by FetchResult
objects built from files in tests/fixtures/, so the whole pipeline including its
gates runs offline and deterministically.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from glinet_rules.config import load_config
from glinet_rules.fetch import FetchResult

FIXTURES = Path(__file__).parent / "fixtures"
FIXTURE_CONFIG = FIXTURES / "config"
REPO_CONFIG = Path(__file__).resolve().parents[1] / "config"


def make_fetch_result(key: str, text: str, *, slug: str = "fixture/source") -> FetchResult:
    """Build a FetchResult from literal text, as if it had been downloaded."""
    data = text.encode("utf-8")
    return FetchResult(
        key=key,
        slug=slug,
        url=f"https://raw.githubusercontent.com/{slug}/deadbeef/{key}.txt",
        revision="d" * 40,
        revision_kind="commit",
        sha256=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
        downloaded_at="2026-01-01T00:00:00Z",
        text=text,
    )


def read_fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


@pytest.fixture
def fixture_config():
    """Config built from tests/fixtures/config/."""
    return load_config(FIXTURE_CONFIG)


@pytest.fixture
def repo_config():
    """The real, shipped config/ directory."""
    return load_config(REPO_CONFIG)


@pytest.fixture
def fixture_sources():
    """Overrides that stand in for the two primary upstream downloads."""
    return {
        "ipv4_primary": make_fetch_result(
            "ipv4_primary", read_fixture("upstream-ipv4.txt"), slug="fixture/ipv4"
        ),
        "domains_primary": make_fetch_result(
            "domains_primary", read_fixture("upstream-domains.txt"), slug="fixture/domains"
        ),
    }
