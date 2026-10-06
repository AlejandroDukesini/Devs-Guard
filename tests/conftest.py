from __future__ import annotations

import datetime as dt
from collections.abc import Iterator
from pathlib import Path

import pytest
import respx

from dep_guard.engine import ScanOptions
from dep_guard.sources.http import HttpClient
from tests.osv_mock import FIXTURES, MockState, install, load_state

# Fixed "today" for every deterministic scan: ignore expiry and goldens depend on it.
TODAY = dt.date(2099, 1, 15)
PROJECTS = FIXTURES / "projects"
GOLDEN = FIXTURES / "golden"


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEPGUARD_CACHE_DIR", str(tmp_path / "cache"))


@pytest.fixture(autouse=True)
def _no_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(HttpClient, "_backoff", lambda self, attempt: 0.0)


@pytest.fixture
def osv() -> Iterator[MockState]:
    state = load_state()
    with respx.mock(assert_all_called=False) as router:
        install(router, state)
        yield state


@pytest.fixture
def opts(tmp_path: Path) -> ScanOptions:
    return ScanOptions(today=TODAY, cache_dir=tmp_path / "cache")
