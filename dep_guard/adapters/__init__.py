"""Registry of manifest/lockfile adapters.

Adding an ecosystem = writing one class with `id`, `matches()` and `parse()`
and appending it to ADAPTERS. Nothing else in the engine changes.
"""

from __future__ import annotations

from dep_guard.adapters.base import Adapter, ParseContext, ParseError, ParseResult
from dep_guard.adapters.cyclonedx import CycloneDxAdapter
from dep_guard.adapters.npm import PackageJsonAdapter, PackageLockAdapter
from dep_guard.adapters.pypi_locks import PoetryLockAdapter, UvLockAdapter
from dep_guard.adapters.pypi_requirements import RequirementsAdapter

ADAPTERS: tuple[Adapter, ...] = (
    PackageLockAdapter(),
    PackageJsonAdapter(),
    PoetryLockAdapter(),
    UvLockAdapter(),
    RequirementsAdapter(),
    CycloneDxAdapter(),
)

# A lockfile in the same directory supersedes the manifest it was generated from.
SUPERSEDED_BY = {"package.json": ("package-lock.json", "npm-shrinkwrap.json")}


def adapter_for(filename: str, parent_dir: str = "") -> Adapter | None:
    for adapter in ADAPTERS:
        if adapter.matches(filename, parent_dir):
            return adapter
    return None


def sniff_adapter(content: str, filename: str = "") -> Adapter | None:
    """For files passed explicitly with a non-standard name (e.g. `pip freeze > deps.txt`)."""
    head = content.lstrip()[:4096]
    if head.startswith("{") and '"bomFormat"' in content[:65536]:
        return CycloneDxAdapter()
    if filename.lower().endswith(".txt"):
        return RequirementsAdapter()
    return None


__all__ = [
    "ADAPTERS",
    "SUPERSEDED_BY",
    "Adapter",
    "ParseContext",
    "ParseError",
    "ParseResult",
    "adapter_for",
    "sniff_adapter",
]
