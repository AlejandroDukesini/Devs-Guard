"""Python lockfiles: poetry.lock and uv.lock.

Both record every resolved package with its exact version and dependency
edges. uv.lock also records the project's own direct dependencies; for
poetry.lock the sibling pyproject.toml provides them (if present).
"""

from __future__ import annotations

import tomllib
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement

from dep_guard import purl
from dep_guard.adapters.base import (
    GraphInfo,
    ParseContext,
    ParseError,
    ParseResult,
    location,
    walk_graph,
)
from dep_guard.models import Component, ComponentStatus, Scope
from dep_guard.textutil import clean, find_line


def _load(content: str) -> dict[str, Any]:
    try:
        return tomllib.loads(content)
    except tomllib.TOMLDecodeError as exc:
        raise ParseError(f"invalid TOML: {clean(str(exc), 120)}") from None


def _norm(name: object) -> str | None:
    return purl.normalize_pypi_name(name) if isinstance(name, str) and name else None


def _req_name(spec: object) -> str | None:
    if not isinstance(spec, str):
        return None
    try:
        return purl.normalize_pypi_name(Requirement(spec).name)
    except InvalidRequirement:
        return None


def _component(
    name: str, version: object, ctx: ParseContext, content: str, info: GraphInfo | None
) -> Component:
    comp = Component(
        ecosystem="PyPI",
        name=name,
        version=version if isinstance(version, str) and version else None,
        purl=purl.build("PyPI", name),
        direct=info.direct if info else None,
        scope=info.scope if info else Scope.UNKNOWN,
        locations=location(ctx, find_line(content, f'name = "{name}"')),
        paths=[info.path] if info else [],
    )
    if comp.version is None:
        comp.status = ComponentStatus.UNRESOLVED
        comp.unresolved_reason = "no version recorded in lockfile"
    return comp


class PoetryLockAdapter:
    id = "poetry-lock"

    def matches(self, filename: str, parent_dir: str) -> bool:
        return filename == "poetry.lock"

    def parse(self, content: str, ctx: ParseContext) -> ParseResult:
        data = _load(content)
        packages = [p for p in data.get("package", []) if isinstance(p, dict)]
        result = ParseResult()
        by_name: dict[str, dict[str, Any]] = {}
        edges: dict[str, list[str]] = {}
        for pkg in packages:
            name = _norm(pkg.get("name"))
            if not name:
                continue
            by_name[name] = pkg
            deps = pkg.get("dependencies")
            edges[name] = (
                [n for d in (deps or {}) if (n := _norm(d))] if isinstance(deps, dict) else []
            )

        prod_roots, dev_roots = _poetry_roots(ctx.read_sibling("pyproject.toml"))
        graph = walk_graph(
            edges,
            [r for r in prod_roots if r in by_name],
            [r for r in dev_roots if r in by_name],
            lambda n: n,
        )

        has_roots = bool(prod_roots or dev_roots)
        for name, pkg in by_name.items():
            info = graph.get(name)
            comp = _component(name, pkg.get("version"), ctx, content, info)
            if has_roots and info is None:
                comp.direct = False  # not reachable from the declared dependencies
            # Poetry 2 records dependency groups per package; Poetry < 1.5 a
            # category. Both are authoritative for runtime vs dev.
            groups = pkg.get("groups")
            if isinstance(groups, list) and groups:
                comp.scope = Scope.PROD if "main" in groups else Scope.DEV
            elif pkg.get("category") in ("main", "dev"):
                comp.scope = Scope.DEV if pkg["category"] == "dev" else Scope.PROD
            result.components.append(_check_source(comp, pkg))
        return result


def _poetry_roots(pyproject: str | None) -> tuple[list[str], list[str]]:
    if not pyproject:
        return [], []
    try:
        data = tomllib.loads(pyproject)
    except tomllib.TOMLDecodeError:
        return [], []
    prod: list[str] = []
    dev: list[str] = []
    project = data.get("project", {})
    if isinstance(project, dict):
        prod += [n for s in project.get("dependencies", []) or [] if (n := _req_name(s))]
    poetry = data.get("tool", {}).get("poetry", {}) if isinstance(data.get("tool"), dict) else {}
    if isinstance(poetry, dict):
        prod += [n for k in (poetry.get("dependencies") or {}) if k != "python" and (n := _norm(k))]
        dev += [n for k in (poetry.get("dev-dependencies") or {}) if (n := _norm(k))]
        groups = poetry.get("group") or {}
        if isinstance(groups, dict):
            for group in groups.values():
                if isinstance(group, dict):
                    dev += [n for k in (group.get("dependencies") or {}) if (n := _norm(k))]
    dep_groups = data.get("dependency-groups") or {}
    if isinstance(dep_groups, dict):
        for specs in dep_groups.values():
            if isinstance(specs, list):
                dev += [n for s in specs if (n := _req_name(s))]
    return prod, dev


def _check_source(comp: Component, pkg: dict[str, Any]) -> Component:
    source = pkg.get("source")
    if isinstance(source, dict) and source.get("type") in ("git", "directory", "file", "url"):
        comp.version = None
        comp.status = ComponentStatus.UNRESOLVED
        comp.unresolved_reason = "non-registry source"
    return comp


class UvLockAdapter:
    id = "uv-lock"

    def matches(self, filename: str, parent_dir: str) -> bool:
        return filename == "uv.lock"

    def parse(self, content: str, ctx: ParseContext) -> ParseResult:
        data = _load(content)
        packages = [p for p in data.get("package", []) if isinstance(p, dict)]
        result = ParseResult()
        by_name: dict[str, dict[str, Any]] = {}
        edges: dict[str, list[str]] = {}
        roots: list[str] = []
        prod_roots: list[str] = []
        dev_roots: list[str] = []

        for pkg in packages:
            name = _norm(pkg.get("name"))
            if not name:
                continue
            by_name[name] = pkg
            raw_source = pkg.get("source")
            source: dict[str, Any] = raw_source if isinstance(raw_source, dict) else {}
            is_root = "editable" in source or "virtual" in source
            prod_children = _names(pkg.get("dependencies"))
            for extra in (pkg.get("optional-dependencies") or {}).values():
                prod_children += _names(extra)
            dev_children: list[str] = []
            for group in (pkg.get("dev-dependencies") or {}).values():
                dev_children += _names(group)
            edges[name] = prod_children + dev_children
            if is_root:
                roots.append(name)
                prod_roots += prod_children
                dev_roots += dev_children

        graph = walk_graph(edges, prod_roots, dev_roots, lambda n: n)
        for name, pkg in by_name.items():
            if name in roots:
                continue
            comp = _component(name, pkg.get("version"), ctx, content, graph.get(name))
            if roots and comp.direct is None:
                comp.direct = False
            pkg_source = pkg.get("source")
            if isinstance(pkg_source, dict) and "registry" not in pkg_source:
                comp.version = None
                comp.status = ComponentStatus.UNRESOLVED
                comp.unresolved_reason = "non-registry source"
            result.components.append(comp)
        return result


def _names(items: object) -> list[str]:
    if not isinstance(items, list):
        return []
    return [n for d in items if isinstance(d, dict) and (n := _norm(d.get("name")))]
