"""Golden algorithm tables shared with the JS engine (fixtures/golden)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from dep_guard import cvss, risk
from dep_guard.models import Component, Finding, Scope, Severity
from dep_guard.versions import compare
from tests.conftest import GOLDEN

VERSIONS = json.loads((GOLDEN / "versions.json").read_text(encoding="utf-8"))["cases"]
CVSS = json.loads((GOLDEN / "cvss.json").read_text(encoding="utf-8"))["cases"]
RISK = json.loads((GOLDEN / "risk.json").read_text(encoding="utf-8"))["cases"]


@pytest.mark.parametrize(("eco", "a", "b", "expected"), VERSIONS)
def test_version_compare(eco: str, a: str, b: str, expected: int | None) -> None:
    assert compare(eco, a, b) == expected
    if expected is not None:
        assert compare(eco, b, a) == -expected  # antisymmetry


@pytest.mark.parametrize(("vector", "score"), CVSS)
def test_cvss_v3_base_score(vector: str, score: float | None) -> None:
    assert cvss.base_score_v3(vector) == score


@pytest.mark.parametrize(
    ("score", "label"),
    [
        (9.0, "CRITICAL"),
        (8.9, "HIGH"),
        (7.0, "HIGH"),
        (6.9, "MEDIUM"),
        (4.0, "MEDIUM"),
        (3.9, "LOW"),
        (0.0, "LOW"),
    ],
)
def test_severity_bands(score: float, label: str) -> None:
    assert cvss.severity_from_score(score).value == label


def test_qualitative_labels() -> None:
    assert cvss.severity_from_label("MODERATE") is Severity.MEDIUM
    assert cvss.severity_from_label("weird") is Severity.UNKNOWN
    assert cvss.severity_from_label(None) is Severity.UNKNOWN


def _finding(case: dict[str, Any]) -> Finding:
    i = case["in"]
    comp = Component(
        ecosystem="npm",
        name="pkg",
        version="1.0.0",
        purl="pkg:npm/pkg",
        direct=i["direct"],
        scope=Scope(i["scope"]),
        paths=[i["path"]] if i["path"] else [],
    )
    return Finding(
        component=comp,
        id="X",
        aliases=["CVE-2099-0001"] if i["cves"] else ["GHSA-x"],
        summary="s",
        severity=Severity(i["severity"]),
        cvss_score=i["cvss"],
        cvss_vector=None,
        cwes=[],
        fixed_versions=[i["fix"]] if i["fix"] else [],
        references=[],
        published=None,
        epss=i["epss"],
        epss_percentile=0.5 if i["epss"] is not None else None,
        kev=i["kev"],
    )


@pytest.mark.parametrize("case", RISK, ids=[c["name"] for c in RISK])
def test_risk_decision_table(case: dict[str, Any]) -> None:
    finding = _finding(case)
    risk.assess(finding)
    assert finding.priority.value == case["priority"]
    assert [r.code for r in finding.reasons] == case["reasons"]
    assert all(r.text for r in finding.reasons)


def test_epss_threshold_is_configurable() -> None:
    finding = _finding(RISK[2])  # EPSS 0.42 MEDIUM prod -> P1 by default
    risk.assess(finding, risk.RiskConfig(epss_threshold=0.5))
    assert finding.priority.value == "P2"
