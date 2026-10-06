"""Deprecated compatibility layer for the original 0.x API.

New code should use dep_guard.adapters. These helpers now return only
dependencies with an exact version: the old behaviour (taking the version
from any operator, e.g. `flask>=2.0` -> 2.0, or `^4.18.2` -> 4.18.2) scanned
versions that were not necessarily installed.
"""

from __future__ import annotations

import warnings

from dep_guard.adapters.base import ParseContext
from dep_guard.adapters.npm import PackageJsonAdapter
from dep_guard.adapters.pypi_requirements import RequirementsAdapter
from dep_guard.models import Component


def _legacy(components: list[Component]) -> list[dict[str, str]]:
    return [
        {"name": c.name, "version": c.version, "ecosystem": c.ecosystem}
        for c in components
        if c.version is not None
    ]


def parse_requirements_txt(content: str) -> list[dict[str, str]]:
    warnings.warn("use dep_guard.adapters", DeprecationWarning, stacklevel=2)
    return _legacy(
        RequirementsAdapter().parse(content, ParseContext("requirements.txt")).components
    )


def parse_package_json(content: str) -> list[dict[str, str]]:
    warnings.warn("use dep_guard.adapters", DeprecationWarning, stacklevel=2)
    return _legacy(PackageJsonAdapter().parse(content, ParseContext("package.json")).components)
