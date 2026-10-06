"""Failure handling: "could not determine" must never be reported as "no vulnerabilities".

Regression for the 0.x bug where any exception or non-200 answer from OSV
produced an empty vulnerability list and the package was printed as SAFE.
"""

from __future__ import annotations

import httpx
import pytest

from dep_guard.engine import ScanOptions, scan
from dep_guard.models import ComponentStatus, Severity
from dep_guard.policy import Verdict
from tests.conftest import PROJECTS
from tests.osv_mock import MockState


@pytest.mark.parametrize("failure", [429, 500, 503, "timeout", "garbage"])
def test_osv_outage_is_incomplete_never_clean(
    osv: MockState, opts: ScanOptions, failure: object
) -> None:
    osv.fail["batch"] = failure
    report = scan(PROJECTS / "py-uv", opts)
    queried = [c for c in report.components if c.version]
    assert queried and all(c.status is ComponentStatus.ERROR for c in queried)
    assert report.policy.verdict is Verdict.INCOMPLETE
    assert report.exit_code == 3
    assert report.sources["osv"].startswith("error")


def test_transient_429_is_retried(osv: MockState, opts: ScanOptions) -> None:
    original = osv.batch
    attempts = {"n": 0}

    def flaky(request):  # type: ignore[no-untyped-def]
        attempts["n"] += 1
        if attempts["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "1"})
        return original(request)

    osv.batch = flaky  # type: ignore[method-assign]
    report = scan(PROJECTS / "py-uv", opts)
    assert attempts["n"] == 2
    assert report.policy.verdict is Verdict.FAIL  # real findings, not INCOMPLETE


def test_allow_incomplete_flag(osv: MockState, opts: ScanOptions) -> None:
    osv.fail["batch"] = 503
    opts.allow_incomplete = True
    assert scan(PROJECTS / "py-uv", opts).exit_code == 0


def test_policy_failure_wins_over_incomplete(osv: MockState, opts: ScanOptions, tmp_path) -> None:  # type: ignore[no-untyped-def]
    project = tmp_path / "p"
    project.mkdir()
    (project / "requirements.txt").write_text("acme-crypto==41.0.0\n", encoding="utf-8")
    (project / "package-lock.json").write_text("{broken", encoding="utf-8")
    report = scan(project, opts)
    assert report.policy.verdict is Verdict.FAIL
    assert report.policy.incomplete_reasons
    assert report.exit_code == 1


def test_advisory_detail_failure_keeps_finding_with_unknown_severity(
    osv: MockState, opts: ScanOptions
) -> None:
    osv.fail["vuln"] = 503
    report = scan(PROJECTS / "py-uv", opts)
    assert report.findings, "vulnerable status is known from querybatch even without details"
    assert all(f.severity is Severity.UNKNOWN for f in report.findings)
    assert any(p.code == "advisory_details_unavailable" for p in report.problems)
    # UNKNOWN severity in production is P2 at least, never silently P3.
    prod = [f for f in report.findings if f.component.scope.value == "prod"]
    assert all(f.priority.value in ("P0", "P1", "P2") for f in prod)


@pytest.mark.parametrize("endpoint", ["epss", "kev"])
def test_enrichment_outage_degrades_gracefully(
    osv: MockState, opts: ScanOptions, endpoint: str
) -> None:
    osv.fail[endpoint] = 503
    report = scan(PROJECTS / "npm-app", opts)
    assert report.sources[endpoint].startswith("error")
    assert any(p.code == f"{endpoint}_unavailable" for p in report.problems)
    assert report.policy.verdict is Verdict.FAIL  # status still known from OSV
    if endpoint == "kev":
        assert all(f.kev is None for f in report.findings)


def test_unknown_package_is_clean_only_when_osv_answered(
    osv: MockState, opts: ScanOptions, tmp_path
) -> None:  # type: ignore[no-untyped-def]
    (tmp_path / "requirements.txt").write_text("totally-unknown-pkg==0.0.1\n", encoding="utf-8")
    report = scan(tmp_path, opts)
    assert report.components[0].status is ComponentStatus.CLEAN
    assert report.exit_code == 0


def test_private_packages_are_never_sent(osv: MockState, opts: ScanOptions, tmp_path) -> None:  # type: ignore[no-untyped-def]
    (tmp_path / "requirements.txt").write_text(
        "acme-crypto==41.0.0\ninternal-billing==1.0\n", encoding="utf-8"
    )
    (tmp_path / "depguard.toml").write_text(
        '[sources]\nprivate_packages = ["internal-*"]\n', encoding="utf-8"
    )
    sent: list[str] = []
    original = osv.batch

    def spy(request):  # type: ignore[no-untyped-def]
        sent.append(request.content.decode())
        return original(request)

    osv.batch = spy  # type: ignore[method-assign]
    report = scan(tmp_path, opts)
    assert sent and all("internal-billing" not in body for body in sent)
    statuses = {c.name: c.status for c in report.components}
    assert statuses["internal-billing"] is ComponentStatus.PRIVATE
