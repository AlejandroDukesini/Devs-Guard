"""CVSS v3.x base score calculator (FIRST CVSS v3.1 specification, section 7).

OSV records carry CVSS *vectors*, not scores, so the score is computed here.
CVSS v4 vectors are recognised but not scored: the v4 algorithm relies on a
large lookup table and we prefer an explicit "unknown" over a wrong number.
The severity then falls back to the advisory's qualitative rating.
"""

from __future__ import annotations

import math

from dep_guard.models import Severity

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def roundup(value: float) -> float:
    """Spec-defined Roundup that avoids floating point artefacts."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def parse_vector(vector: str) -> dict[str, str] | None:
    parts = vector.strip().split("/")
    if not parts or not parts[0].startswith("CVSS:3."):
        return None
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        if ":" not in part:
            return None
        key, _, value = part.partition(":")
        if key in metrics:
            return None
        metrics[key] = value
    if any(k not in metrics for k in _REQUIRED):
        return None
    return metrics


def base_score_v3(vector: str) -> float | None:
    m = parse_vector(vector)
    if m is None:
        return None
    try:
        changed = {"U": False, "C": True}[m["S"]]
        av, ac, ui = _AV[m["AV"]], _AC[m["AC"]], _UI[m["UI"]]
        pr = (_PR_CHANGED if changed else _PR_UNCHANGED)[m["PR"]]
        c, i, a = _CIA[m["C"]], _CIA[m["I"]], _CIA[m["A"]]
    except KeyError:
        return None

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if changed:
        return roundup(min(1.08 * (impact + exploitability), 10))
    return roundup(min(impact + exploitability, 10))


def severity_from_score(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


_QUALITATIVE = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def severity_from_label(label: object) -> Severity:
    if isinstance(label, str):
        return _QUALITATIVE.get(label.strip().upper(), Severity.UNKNOWN)
    return Severity.UNKNOWN
