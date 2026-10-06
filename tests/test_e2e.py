"""End-to-end: project -> scan (mocked OSV/EPSS/KEV) -> report == golden."""

from __future__ import annotations

import json

import pytest

from dep_guard.engine import ScanOptions, scan
from dep_guard.models import ComponentStatus
from dep_guard.reporters import json_report
from tests.conftest import GOLDEN, PROJECTS, TODAY
from tests.osv_mock import FIXTURES, MockState
from tests.regen_golden import CASES, normalise


@pytest.mark.parametrize(("name", "project", "config"), CASES, ids=[c[0] for c in CASES])
def test_report_matches_golden(
    osv: MockState, opts: ScanOptions, name: str, project: str, config: str | None
) -> None:
    if config:
        opts.config_path = FIXTURES / config
    report = scan(PROJECTS / project, opts)
    expected = json.loads((GOLDEN / f"report-{name}.json").read_text(encoding="utf-8"))
    assert normalise(json_report.to_dict(report)) == expected


def test_report_is_deterministic(osv: MockState, opts: ScanOptions) -> None:
    first = normalise(json_report.to_dict(scan(PROJECTS / "npm-app", opts)))
    second = normalise(
        json_report.to_dict(scan(PROJECTS / "npm-app", ScanOptions(today=TODAY, use_cache=False)))
    )
    assert first == second


def test_second_scan_uses_cache_for_advisories(osv: MockState, opts: ScanOptions) -> None:
    scan(PROJECTS / "py-uv", opts)
    vuln_calls = osv.calls["vuln"]
    scan(PROJECTS / "py-uv", opts)
    assert osv.calls["vuln"] == vuln_calls  # id@modified cache hit, no refetch
    assert osv.calls["batch"] == 2  # status is always re-queried online


def test_offline_mode_uses_cache_and_never_calls_network(osv: MockState, opts: ScanOptions) -> None:
    online = normalise(json_report.to_dict(scan(PROJECTS / "py-uv", opts)))
    calls = dict(osv.calls)
    opts.offline = True
    offline = json_report.to_dict(scan(PROJECTS / "py-uv", opts))
    assert osv.calls == calls
    assert offline["sources"]["osv"] == "offline-cache"
    assert offline["findings"] == online["findings"]


def test_offline_without_cache_is_incomplete_not_clean(osv: MockState, opts: ScanOptions) -> None:
    opts.offline = True
    report = scan(PROJECTS / "py-uv", opts)
    assert report.exit_code == 3
    assert all(c.status is not ComponentStatus.CLEAN for c in report.components)


def test_batches_are_used(osv: MockState, opts: ScanOptions) -> None:
    scan(PROJECTS / "npm-app", opts)
    assert osv.calls["batch"] == 1  # 7 resolvable packages, one request
