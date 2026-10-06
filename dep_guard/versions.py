"""Version comparison per ecosystem.

Only used to pick *which* fixed version applies to the installed version.
Deciding whether a version is affected is delegated to OSV (we always query
with an exact version), so a comparison failure here can never hide a
vulnerability: it only degrades the remediation advice.
"""

from __future__ import annotations

import re
from typing import Any

from packaging.version import InvalidVersion, Version

_SEMVER = re.compile(
    r"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)


def _cmp(a: Any, b: Any) -> int:
    return int(a > b) - int(a < b)


def _semver_key(v: str) -> tuple[int, int, int, list[str]] | None:
    m = _SEMVER.match(v.strip())
    if not m:
        return None
    pre = m.group(4).split(".") if m.group(4) else []
    return int(m.group(1)), int(m.group(2)), int(m.group(3)), pre


def _compare_prerelease(a: list[str], b: list[str]) -> int:
    # A version without pre-release has higher precedence (semver §11.3).
    if not a or not b:
        return _cmp(not a, not b)
    for x, y in zip(a, b, strict=False):
        if x == y:
            continue
        xn, yn = x.isdigit(), y.isdigit()
        if xn and yn:
            return _cmp(int(x), int(y))
        if xn != yn:
            return -1 if xn else 1  # numeric identifiers sort first
        return _cmp(x, y)
    return _cmp(len(a), len(b))


def compare_semver(a: str, b: str) -> int | None:
    ka, kb = _semver_key(a), _semver_key(b)
    if ka is None or kb is None:
        return None
    core = _cmp(ka[:3], kb[:3])
    return core if core else _compare_prerelease(ka[3], kb[3])


def compare_pep440(a: str, b: str) -> int | None:
    try:
        return _cmp(Version(a), Version(b))
    except InvalidVersion:
        return None


def compare(ecosystem: str, a: str, b: str) -> int | None:
    """Return -1/0/1, or None when the versions cannot be ordered reliably."""
    if ecosystem == "PyPI":
        return compare_pep440(a, b)
    if ecosystem == "npm":
        return compare_semver(a, b)
    return None


def is_semver(v: str) -> bool:
    return _semver_key(v) is not None
