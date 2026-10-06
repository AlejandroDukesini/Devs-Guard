"""npm: package-lock.json / npm-shrinkwrap.json (v2, v3) and package.json.

The lockfile is the source of truth: it records the exact version of every
installed package, including transitive ones, and the tree that pulled them
in. package.json alone only yields direct dependencies with ranges, so it is
parsed only when no lockfile sits next to it, and ranges stay UNRESOLVED.
"""

from __future__ import annotations

import json
from typing import Any

from dep_guard import purl
from dep_guard.adapters.base import (
    ParseContext,
    ParseError,
    ParseResult,
    location,
    walk_graph,
)
from dep_guard.models import Component, ComponentStatus, Problem, Scope
from dep_guard.textutil import clean, find_line
from dep_guard.versions import is_semver

LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json")
_DEP_FIELDS = (
    ("dependencies", Scope.PROD),
    ("optionalDependencies", Scope.PROD),
    ("devDependencies", Scope.DEV),
)
_NON_REGISTRY = ("file:", "link:", "workspace:", "git", "github:", "gitlab:", "bitbucket:", "http")


def _load_object(content: str, rel_path: str) -> dict[str, Any]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ParseError(f"invalid JSON at line {exc.lineno}") from None
    if not isinstance(data, dict):
        raise ParseError("top-level JSON value is not an object")
    return data


def _exact(spec: str) -> str | None:
    candidate = spec.strip().removeprefix("=").removeprefix("v").strip()
    return candidate if is_semver(candidate) else None


def _unresolved_reason(spec: str) -> str:
    s = spec.strip()
    if s.startswith(_NON_REGISTRY) or ("/" in s and not s.startswith("npm:")):
        return "non-registry source"
    if s in ("", "*", "latest", "x"):
        return "no version constraint"
    return f"version range ({clean(s, 60)}); commit a package-lock.json"


class PackageJsonAdapter:
    id = "npm-package-json"

    def matches(self, filename: str, parent_dir: str) -> bool:
        return filename == "package.json"

    def parse(self, content: str, ctx: ParseContext) -> ParseResult:
        data = _load_object(content, ctx.rel_path)
        result = ParseResult()
        result.problems.append(
            Problem(
                "no_lockfile",
                "package.json without package-lock.json: only direct dependencies are visible "
                "and ranges cannot be resolved",
                ctx.rel_path,
            )
        )
        for field_name, scope in _DEP_FIELDS:
            section = data.get(field_name)
            if not isinstance(section, dict):
                continue
            for raw_name, raw_spec in section.items():
                if not isinstance(raw_name, str) or not isinstance(raw_spec, str):
                    continue
                name, spec = raw_name, raw_spec
                if spec.startswith("npm:"):  # alias: "x": "npm:real-pkg@1.2.3"
                    target = spec[4:]
                    at = target.rfind("@")
                    if at > 0:
                        name, spec = target[:at], target[at + 1 :]
                version = _exact(spec)
                comp = Component(
                    ecosystem="npm",
                    name=clean(name, 214),
                    version=version,
                    purl=purl.build("npm", name),
                    direct=True,
                    scope=scope,
                    locations=location(ctx, find_line(content, json.dumps(raw_name))),
                    paths=[[clean(name, 214)]],
                )
                if version is None:
                    comp.status = ComponentStatus.UNRESOLVED
                    comp.unresolved_reason = _unresolved_reason(spec)
                result.components.append(comp)
        return result


class PackageLockAdapter:
    id = "npm-package-lock"

    def matches(self, filename: str, parent_dir: str) -> bool:
        return filename in LOCKFILES

    def parse(self, content: str, ctx: ParseContext) -> ParseResult:
        data = _load_object(content, ctx.rel_path)
        lock_version = data.get("lockfileVersion")
        packages = data.get("packages")
        if lock_version not in (2, 3) or not isinstance(packages, dict):
            raise ParseError(
                f"unsupported lockfileVersion {clean(str(lock_version), 10)}; "
                "regenerate it with npm >= 7"
            )

        result = ParseResult()
        entries: dict[str, dict[str, Any]] = {
            k: v for k, v in packages.items() if isinstance(k, str) and isinstance(v, dict)
        }

        # Roots: the project itself ("") and workspace packages (keys outside node_modules).
        roots = [k for k in entries if k == "" or "node_modules/" not in k]
        prod_roots: list[str] = []
        dev_roots: list[str] = []
        edges: dict[str, list[str]] = {}
        for key, entry in entries.items():
            children: list[str] = []
            for field_name, scope in (*_DEP_FIELDS, ("peerDependencies", Scope.PROD)):
                deps = entry.get(field_name)
                if not isinstance(deps, dict):
                    continue
                for dep_name in deps:
                    target = _resolve(entries, key, dep_name)
                    if target is None:
                        continue
                    children.append(target)
                    if key in roots and field_name != "peerDependencies":
                        (dev_roots if scope is Scope.DEV else prod_roots).append(target)
            edges[key] = children

        def label(key: str) -> str:
            return _package_name(key, entries[key])

        graph = walk_graph(edges, prod_roots, dev_roots, label)

        for key, entry in entries.items():
            if key in roots or entry.get("link") is True:
                continue
            name = _package_name(key, entry)
            version = entry.get("version")
            info = graph.get(key)
            # npm itself flags dev-only packages; absence of the flag means the
            # package ships with production installs.
            dev_only = entry.get("dev") is True or entry.get("devOptional") is True
            scope = Scope.DEV if dev_only else Scope.PROD
            comp = Component(
                ecosystem="npm",
                name=clean(name, 214),
                version=version if isinstance(version, str) and version else None,
                purl=purl.build("npm", name),
                direct=info.direct if info else False,
                scope=scope,
                locations=location(ctx, find_line(content, json.dumps(key))),
                paths=[info.path] if info else [],
            )
            resolved = entry.get("resolved")
            if comp.version is None:
                comp.unresolved_reason = "no version recorded in lockfile"
            elif isinstance(resolved, str) and not resolved.startswith(("https://", "http://")):
                comp.unresolved_reason = "non-registry source"
                comp.version = None
            if comp.version is None:
                comp.status = ComponentStatus.UNRESOLVED
            result.components.append(comp)
        return result


def _package_name(key: str, entry: dict[str, Any]) -> str:
    explicit = entry.get("name")
    if isinstance(explicit, str) and explicit and "node_modules/" in key:
        return explicit  # aliased install ("npm:real-name@x")
    return key.rsplit("node_modules/", 1)[-1] if "node_modules/" in key else (explicit or key)


def _resolve(entries: dict[str, Any], from_key: str, dep: str) -> str | None:
    """Node's module resolution: nearest node_modules walking up the tree."""
    base = from_key
    while True:
        candidate = f"{base}/node_modules/{dep}" if base else f"node_modules/{dep}"
        if candidate in entries:
            return candidate
        if not base:
            return None
        idx = base.rfind("/node_modules/")
        if idx >= 0:
            base = base[:idx]
        elif base.startswith("node_modules/"):
            base = ""
        else:  # workspace folder: fall back to the root node_modules
            base = ""
