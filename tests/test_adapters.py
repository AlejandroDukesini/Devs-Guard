"""Adapter edge cases beyond the end-to-end goldens."""

from __future__ import annotations

import json
from typing import Any

import pytest

from dep_guard import purl
from dep_guard.adapters import ParseContext, ParseError, ParseResult, adapter_for, sniff_adapter
from dep_guard.adapters.npm import PackageJsonAdapter, PackageLockAdapter
from dep_guard.adapters.pypi_locks import PoetryLockAdapter, UvLockAdapter
from dep_guard.adapters.pypi_requirements import RequirementsAdapter
from dep_guard.models import ComponentStatus, Scope
from tests.conftest import PROJECTS


def _parse(adapter: Any, content: str, path: str = "f") -> ParseResult:
    result: ParseResult = adapter.parse(content, ParseContext(path))
    return result


class TestRequirements:
    def test_regression_range_operators_are_not_scanned_as_versions(self) -> None:
        # 0.x bug: `flask>=2.0.0` scanned 2.0.0 and `urllib3!=1.25.0` scanned 1.25.0.
        result = _parse(RequirementsAdapter(), "flask>=2.0.0\nurllib3!=1.25.0\nrequests==2.28.1\n")
        by_name = {c.name: c for c in result.components}
        assert by_name["flask"].version is None
        assert by_name["flask"].status is ComponentStatus.UNRESOLVED
        assert by_name["urllib3"].version is None
        assert by_name["requests"].version == "2.28.1"

    def test_names_with_dots_extras_and_markers(self) -> None:
        content = 'zope.interface==6.0\nuvicorn[standard]==0.30.0 ; python_version>"3"\n'
        result = _parse(RequirementsAdapter(), content)
        assert [(c.name, c.version) for c in result.components] == [
            ("zope-interface", "6.0"),
            ("uvicorn", "0.30.0"),
        ]

    def test_dev_scope_from_filename(self) -> None:
        req = RequirementsAdapter()
        assert _parse(req, "a==1", "requirements-dev.txt").components[0].scope is Scope.DEV
        assert _parse(req, "a==1", "requirements/test.txt").components[0].scope is Scope.DEV
        assert _parse(req, "a==1", "requirements-precise.txt").components[0].scope is Scope.PROD

    def test_credentials_in_options_are_never_echoed(self) -> None:
        result = _parse(RequirementsAdapter(), "-r https://user:hunter2@x.invalid/r.txt\n")
        assert result.problems
        assert all("hunter2" not in p.message for p in result.problems)

    def test_filename_matching(self) -> None:
        req = RequirementsAdapter()
        assert req.matches("requirements.txt", "x")
        assert req.matches("dev-requirements.txt", "x")
        assert req.matches("base.txt", "requirements")
        assert not req.matches("notes.txt", "x")


class TestNpm:
    def test_lockfile_v1_is_rejected_explicitly(self) -> None:
        with pytest.raises(ParseError, match="lockfileVersion"):
            _parse(PackageLockAdapter(), json.dumps({"lockfileVersion": 1, "dependencies": {}}))

    def test_non_object_json(self) -> None:
        with pytest.raises(ParseError):
            _parse(PackageJsonAdapter(), "[1, 2]")

    def test_nested_resolution_prefers_closest_node_modules(self) -> None:
        content = (PROJECTS / "npm-app" / "package-lock.json").read_text(encoding="utf-8")
        comps = {(c.name, c.version): c for c in _parse(PackageLockAdapter(), content).components}
        assert comps[("acme-qs", "5.1.0")].paths == [["acme-test", "acme-qs"]]
        assert comps[("acme-qs", "5.1.0")].scope is Scope.DEV
        assert comps[("acme-qs", "6.2.0")].paths == [["acme-router", "acme-qs"]]
        assert comps[("acme-qs", "6.2.0")].scope is Scope.PROD

    def test_workspace_links_are_not_components(self) -> None:
        lock = {
            "lockfileVersion": 3,
            "packages": {
                "": {"workspaces": ["packages/*"]},
                "node_modules/ws-a": {"resolved": "packages/a", "link": True},
                "packages/a": {"name": "ws-a", "version": "1.0.0", "dependencies": {"dep": "^1"}},
                "node_modules/dep": {"version": "1.2.3", "resolved": "https://r/dep.tgz"},
            },
        }
        comps = _parse(PackageLockAdapter(), json.dumps(lock)).components
        assert [(c.name, c.version, c.direct) for c in comps] == [("dep", "1.2.3", True)]


class TestPythonLocks:
    def test_uv_root_is_not_a_component(self) -> None:
        content = (PROJECTS / "py-uv" / "uv.lock").read_text(encoding="utf-8")
        names = {c.name for c in _parse(UvLockAdapter(), content).components}
        assert "demo-api" not in names

    def test_poetry_without_pyproject_uses_groups(self) -> None:
        content = (PROJECTS / "py-poetry" / "poetry.lock").read_text(encoding="utf-8")
        comps = {c.name: c for c in _parse(PoetryLockAdapter(), content).components}
        assert comps["acme-lint"].scope is Scope.DEV
        assert comps["acme-markup"].scope is Scope.PROD  # in main and dev -> shipped
        assert comps["acme-web"].direct is None  # unknown without pyproject.toml

    def test_invalid_toml(self) -> None:
        with pytest.raises(ParseError, match="invalid TOML"):
            _parse(UvLockAdapter(), "[[package]\nname=")


def test_purl_roundtrip() -> None:
    assert purl.build("npm", "@acme/logger") == "pkg:npm/%40acme/logger"
    parsed = purl.parse("pkg:npm/%40acme/logger@1.4.0")
    assert parsed is not None
    assert (parsed.osv_name, parsed.version) == ("@acme/logger", "1.4.0")
    maven = purl.parse("pkg:maven/com.acme/acme-json@2.9.0?type=jar")
    assert maven is not None
    assert (maven.osv_name, maven.ecosystem) == ("com.acme:acme-json", "Maven")
    pypi = purl.parse("pkg:pypi/Foo_Bar@1")
    assert pypi is not None and pypi.name == "foo-bar"
    assert purl.parse("not-a-purl") is None


def test_adapter_selection_and_sniffing() -> None:
    assert adapter_for("package-lock.json") is not None
    assert adapter_for("README.md") is None
    assert sniff_adapter('{"bomFormat": "CycloneDX"}') is not None
    assert sniff_adapter("hello") is None
