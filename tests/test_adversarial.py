"""Negative and adversarial inputs not covered elsewhere.

Ambiguous names, incomplete lockfiles and empty manifests must neither crash
the scan nor produce a reassuring answer the data does not support.
"""

from __future__ import annotations

import json
from pathlib import Path

from dep_guard.adapters import ParseContext, adapter_for
from dep_guard.engine import ScanOptions, collect, scan
from dep_guard.models import ComponentStatus
from dep_guard.policy import Verdict


def _write(root: Path, name: str, text: str) -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_ambiguous_python_names_are_one_package(tmp_path: Path) -> None:
    """PEP 503: Django/django and zope.interface/Zope_Interface are the same project."""
    _write(tmp_path, "requirements.txt", "Django==3.2.0\nzope.interface==5.0.0\n")
    _write(tmp_path, "requirements-dev.txt", "django==3.2.0\nZope_Interface==5.0.0\n")
    _, components, _ = collect(tmp_path)
    assert sorted((c.name, c.version) for c in components) == [
        ("django", "3.2.0"),
        ("zope-interface", "5.0.0"),
    ]
    assert all(len(c.locations) == 2 for c in components)


def test_npm_scoped_and_lookalike_names_stay_distinct(tmp_path: Path) -> None:
    lock = {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"@types/node": "1.0.0", "types-node": "1.0.0"}},
            "node_modules/@types/node": {"version": "1.0.0", "resolved": "https://r/x.tgz"},
            "node_modules/types-node": {"version": "1.0.0", "resolved": "https://r/y.tgz"},
        },
    }
    _write(tmp_path, "package-lock.json", json.dumps(lock))
    _, components, _ = collect(tmp_path)
    assert sorted(c.purl for c in components) == ["pkg:npm/%40types/node", "pkg:npm/types-node"]


def test_incomplete_lockfiles_degrade_without_inventing_data() -> None:
    # pnpm importer pointing at a package missing from `packages`.
    pnpm = (
        "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n"
        "      ghost:\n        specifier: ^1.0.0\n        version: 1.0.0\n"
        "packages:\n  real@2.0.0:\n    resolution: {integrity: sha512-x}\n"
        "snapshots:\n  real@2.0.0:\n    dependencies:\n      missing-child: 3.0.0\n"
    )
    adapter = adapter_for("pnpm-lock.yaml")
    assert adapter is not None
    result = adapter.parse(pnpm, ParseContext("pnpm-lock.yaml"))
    assert [(c.name, c.version, c.direct) for c in result.components] == [("real", "2.0.0", False)]

    # Cargo.lock dependency naming a crate that is not in the lock.
    cargo = (
        'version = 3\n[[package]]\nname = "app"\nversion = "0.1.0"\ndependencies = ["gone"]\n'
        '[[package]]\nname = "kept"\nversion = "1.0.0"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
    )
    cargo_adapter = adapter_for("Cargo.lock")
    assert cargo_adapter is not None
    crates = cargo_adapter.parse(cargo, ParseContext("Cargo.lock")).components
    assert [(c.name, c.direct) for c in crates] == [("kept", False)]

    # npm lockfile entry without a version.
    npm_lock = {
        "lockfileVersion": 3,
        "packages": {"": {}, "node_modules/noversion": {"resolved": "https://r/z.tgz"}},
    }
    npm_adapter = adapter_for("package-lock.json")
    assert npm_adapter is not None
    (comp,) = npm_adapter.parse(json.dumps(npm_lock), ParseContext("package-lock.json")).components
    assert comp.status is ComponentStatus.UNRESOLVED and comp.unresolved_reason


def test_empty_manifest_is_analysed_and_passes_only_because_it_is_empty(tmp_path: Path) -> None:
    _write(tmp_path, "requirements.txt", "# no dependencies yet\n")
    report = scan(tmp_path, ScanOptions(offline=True, cache_dir=tmp_path / "c"))
    assert report.components == []
    assert [m.path for m in report.manifests] == ["requirements.txt"]
    assert report.policy.verdict is Verdict.PASS  # one manifest, analysed, nothing in it


def test_nonexistent_version_is_never_reported_clean_offline(tmp_path: Path) -> None:
    _write(tmp_path, "requirements.txt", "requests==99.0.0\n")
    report = scan(tmp_path, ScanOptions(offline=True, cache_dir=tmp_path / "c"))
    (comp,) = report.components
    assert comp.status is ComponentStatus.ERROR  # not in the cache -> unknown, not clean
    assert report.policy.verdict is Verdict.INCOMPLETE
