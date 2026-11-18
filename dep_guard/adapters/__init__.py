"""Registry of manifest/lockfile adapters.

Adding an ecosystem = writing one class with `id`, `matches()` and `parse()`
and appending it to ADAPTERS. Nothing else in the engine changes.
"""

from __future__ import annotations

from dep_guard.adapters.base import Adapter, ParseContext, ParseError, ParseResult
from dep_guard.adapters.cyclonedx import CycloneDxAdapter
from dep_guard.adapters.dotnet_jvm import (
    GradleLockfileAdapter,
    MsbuildProjectAdapter,
    NugetLockAdapter,
    PomAdapter,
)
from dep_guard.adapters.js_locks import PnpmLockAdapter, YarnLockAdapter
from dep_guard.adapters.npm import PackageJsonAdapter, PackageLockAdapter
from dep_guard.adapters.pypi_locks import PoetryLockAdapter, UvLockAdapter
from dep_guard.adapters.pypi_requirements import RequirementsAdapter
from dep_guard.adapters.python_manifests import PipfileLockAdapter, PyprojectAdapter
from dep_guard.adapters.rust_go_php import (
    CargoLockAdapter,
    ComposerJsonAdapter,
    ComposerLockAdapter,
    GoModAdapter,
)

ADAPTERS: tuple[Adapter, ...] = (
    PackageLockAdapter(),
    PnpmLockAdapter(),
    YarnLockAdapter(),
    PackageJsonAdapter(),
    PoetryLockAdapter(),
    UvLockAdapter(),
    PipfileLockAdapter(),
    RequirementsAdapter(),
    PyprojectAdapter(),
    CargoLockAdapter(),
    GoModAdapter(),
    ComposerLockAdapter(),
    ComposerJsonAdapter(),
    NugetLockAdapter(),
    MsbuildProjectAdapter(),
    PomAdapter(),
    GradleLockfileAdapter(),
    CycloneDxAdapter(),
)

# Adapter id -> lockfiles that, in the same directory, supersede that manifest
# (the lockfile records what is actually installed).
SUPERSEDED_BY = {
    "npm-package-json": ("package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock"),
    "pyproject": ("poetry.lock", "uv.lock", "Pipfile.lock"),
    "composer-json": ("composer.lock",),
    "nuget-project": ("packages.lock.json",),
}

# Recognised dependency files that no adapter can analyse. Each entry is
# (lockfile that makes it redundant when found here or in a parent directory,
# advice). They are reported so a mixed repository never looks fully covered.
NOT_ANALYSED = {
    "Cargo.toml": ("Cargo.lock", "commit Cargo.lock to analyse Rust dependencies"),
    "build.gradle": ("gradle.lockfile", "enable Gradle dependency locking (gradle.lockfile)"),
    "build.gradle.kts": ("gradle.lockfile", "enable Gradle dependency locking (gradle.lockfile)"),
    "Pipfile": ("Pipfile.lock", "commit Pipfile.lock"),
    "Gemfile.lock": (None, "RubyGems lockfiles are not supported; scan a CycloneDX SBOM"),
    "pdm.lock": (None, "pdm.lock is not supported; export with `pdm export` or scan an SBOM"),
    "bun.lock": (None, "bun.lock is not supported; scan a CycloneDX SBOM"),
    "bun.lockb": (None, "bun.lockb is binary and not supported; scan a CycloneDX SBOM"),
    "pubspec.lock": (None, "Dart/Flutter lockfiles are not supported; scan a CycloneDX SBOM"),
    "mix.lock": (None, "Elixir lockfiles are not supported; scan a CycloneDX SBOM"),
    "Package.resolved": (None, "SwiftPM lockfiles are not supported; scan a CycloneDX SBOM"),
}


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
    "NOT_ANALYSED",
    "SUPERSEDED_BY",
    "Adapter",
    "ParseContext",
    "ParseError",
    "ParseResult",
    "adapter_for",
    "sniff_adapter",
]
