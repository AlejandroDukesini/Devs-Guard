"""Python manifests without a supported lockfile: pyproject.toml and Pipfile.lock.

pyproject.toml declares *direct* dependencies only, usually as ranges:
- PEP 621 `[project] dependencies` and `optional-dependencies` (runtime);
- PEP 735 `[dependency-groups]` (development);
- Poetry `[tool.poetry.dependencies]` (runtime) and dev groups.
Only exact pins (`==1.2.3`, or a bare `1.2.3` in Poetry) are queried; ranges
stay UNRESOLVED with the reason. It is skipped when poetry.lock / uv.lock /
Pipfile.lock sits next to it (the lockfile is the source of truth).

Pipfile.lock records every installed package with an exact `==` version in
`default` (runtime) and `develop` (development). The sibling Pipfile, when
present, tells which ones were declared directly.
"""

from __future__ import annotations

import re
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement

from dep_guard import purl
from dep_guard.adapters.base import ParseContext, ParseError, ParseResult, make_component
from dep_guard.adapters.safe_formats import load_json_object, load_toml
from dep_guard.models import Component, Problem, Scope
from dep_guard.textutil import clean, find_line

_POETRY_EXACT = re.compile(r"^=?=?\s*(\d+(?:\.\d+)*(?:[-.]?(?:a|b|rc|post|dev)\d*)*)$")


def _pep508(spec: str, scope: Scope, ctx: ParseContext, content: str) -> Component | None:
    try:
        req = Requirement(spec)
    except InvalidRequirement:
        return None
    name = purl.normalize_pypi_name(req.name)
    specs = list(req.specifier)
    version: str | None = None
    reason: str | None = None
    if req.url:
        reason = "direct URL reference"
    elif len(specs) == 1 and specs[0].operator in ("==", "===") and "*" not in specs[0].version:
        version = specs[0].version
    elif not specs:
        reason = "no version specified"
    else:
        reason = f"not pinned ({clean(str(req.specifier), 80)}); commit a lockfile"
    return make_component(
        "PyPI",
        name,
        version,
        ctx,
        find_line(content, req.name),
        direct=True,
        scope=scope,
        unresolved_reason=reason,
    )


def _poetry_dep(
    raw_name: str, value: object, scope: Scope, ctx: ParseContext, content: str
) -> Component:
    name = purl.normalize_pypi_name(raw_name)
    constraint: object = value
    reason: str | None = None
    if isinstance(value, dict):
        if any(k in value for k in ("git", "path", "url")):
            reason = "non-registry source"
        constraint = value.get("version")
    version = None
    if reason is None:
        match = _POETRY_EXACT.match(constraint.strip()) if isinstance(constraint, str) else None
        if match:
            version = match.group(1)
        else:
            shown = clean(str(constraint), 60) if constraint else "none"
            reason = f"not pinned ({shown}); commit poetry.lock"
    return make_component(
        "PyPI",
        name,
        version,
        ctx,
        find_line(content, raw_name),
        direct=True,
        scope=scope,
        unresolved_reason=reason,
    )


class PyprojectAdapter:
    id = "pyproject"

    def matches(self, filename: str, parent_dir: str) -> bool:
        return filename == "pyproject.toml"

    def parse(self, content: str, ctx: ParseContext) -> ParseResult:
        data = load_toml(content)
        result = ParseResult()
        declared: list[tuple[object, Scope]] = []
        project = data.get("project")
        if isinstance(project, dict):
            declared += [(s, Scope.PROD) for s in project.get("dependencies") or []]
            extras = project.get("optional-dependencies") or {}
            if isinstance(extras, dict):
                for specs in extras.values():
                    declared += [(s, Scope.PROD) for s in specs or [] if isinstance(specs, list)]
        groups = data.get("dependency-groups") or {}
        if isinstance(groups, dict):
            for specs in groups.values():
                if isinstance(specs, list):
                    declared += [(s, Scope.DEV) for s in specs if isinstance(s, str)]
        for spec, scope in declared:
            if not isinstance(spec, str):
                continue
            comp = _pep508(spec, scope, ctx, content)
            if comp is None:
                result.problems.append(
                    Problem(
                        "invalid_requirement",
                        f"not a valid PEP 508 requirement: {clean(spec, 80)}",
                        ctx.rel_path,
                    )
                )
            else:
                result.components.append(comp)

        tool = data.get("tool")
        poetry = tool.get("poetry") if isinstance(tool, dict) else None
        if isinstance(poetry, dict):
            sections: list[tuple[object, Scope]] = [
                (poetry.get("dependencies"), Scope.PROD),
                (poetry.get("dev-dependencies"), Scope.DEV),
            ]
            poetry_groups = poetry.get("group")
            if isinstance(poetry_groups, dict):
                sections += [
                    (g.get("dependencies"), Scope.DEV)
                    for g in poetry_groups.values()
                    if isinstance(g, dict)
                ]
            for section, scope in sections:
                if not isinstance(section, dict):
                    continue
                for raw_name, value in section.items():
                    if str(raw_name).lower() == "python":
                        continue
                    result.components.append(_poetry_dep(str(raw_name), value, scope, ctx, content))
        if result.components and all(c.version is None for c in result.components):
            result.problems.append(
                Problem(
                    "no_lockfile",
                    "pyproject.toml declares ranges only: commit a lockfile (uv.lock, "
                    "poetry.lock) or a pinned requirements file to check installed versions",
                    ctx.rel_path,
                )
            )
        return result


def _pipfile_direct(pipfile: str | None) -> set[str]:
    if not pipfile:
        return set()
    try:
        data = load_toml(pipfile)
    except (ParseError, RecursionError):  # a broken Pipfile only loses the direct hint
        return set()
    names: set[str] = set()
    for section in ("packages", "dev-packages"):
        block = data.get(section)
        if isinstance(block, dict):
            names |= {purl.normalize_pypi_name(str(n)) for n in block}
    return names


class PipfileLockAdapter:
    id = "pipfile-lock"

    def matches(self, filename: str, parent_dir: str) -> bool:
        return filename == "Pipfile.lock"

    def parse(self, content: str, ctx: ParseContext) -> ParseResult:
        data = load_json_object(content)
        direct = _pipfile_direct(ctx.read_sibling("Pipfile"))
        result = ParseResult()
        for section, scope in (("default", Scope.PROD), ("develop", Scope.DEV)):
            block: Any = data.get(section)
            if not isinstance(block, dict):
                continue
            for raw_name, entry in block.items():
                if not isinstance(entry, dict):
                    continue
                name = purl.normalize_pypi_name(str(raw_name))
                version: str | None = None
                reason: str | None = None
                raw_version = entry.get("version")
                if any(k in entry for k in ("git", "path", "file", "editable")):
                    reason = "non-registry source"
                elif isinstance(raw_version, str) and raw_version.startswith("=="):
                    version = raw_version[2:].strip()
                else:
                    reason = "no exact version recorded"
                result.components.append(
                    make_component(
                        "PyPI",
                        name,
                        version,
                        ctx,
                        find_line(content, f'"{raw_name}"'),
                        direct=(name in direct) if direct else None,
                        scope=scope,
                        unresolved_reason=reason,
                    )
                )
        return result
