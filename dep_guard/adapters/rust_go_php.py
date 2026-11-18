"""Cargo.lock (Rust), go.mod (Go) and composer.lock / composer.json (PHP).

Cargo.lock
  Every resolved crate with its exact version and `source`. Entries without
  a source are the workspace's own crates (roots); their dependencies are
  the direct ones. A sibling Cargo.toml separates `[dev-dependencies]`.
  `dependencies` entries are "name", "name version" or
  "name version (source)" when several versions coexist.

go.mod
  Since Go 1.17 go.mod lists every module in the build list (the
  `// indirect` comment marks transitive ones), with exact versions chosen
  by minimal version selection. `replace` directives are honoured: the
  replacement module is what gets compiled; a local-path replacement has no
  registry version. go.sum is not used: it lists hashes of many versions,
  not the selected set.

composer.lock
  `packages` (runtime) and `packages-dev` (development) with exact versions;
  edges come from each package's `require`. composer.json alone is parsed
  only when no composer.lock sits next to it (constraints stay UNRESOLVED).
"""

from __future__ import annotations

import re
from typing import Any

from dep_guard.adapters.base import (
    ParseContext,
    ParseError,
    ParseResult,
    make_component,
    walk_graph,
)
from dep_guard.adapters.safe_formats import load_json_object, load_toml
from dep_guard.models import Problem, Scope
from dep_guard.textutil import clean, find_line

# ------------------------------------------------------------------- Cargo

_CRATES_SOURCES = (
    "registry+https://github.com/rust-lang/crates.io-index",
    "sparse+https://index.crates.io/",
)


def _cargo_dev_only(cargo_toml: str | None) -> set[str]:
    if not cargo_toml:
        return set()
    try:
        data = load_toml(cargo_toml)
    except (ParseError, RecursionError):
        return set()
    runtime = set(data.get("dependencies") or {}) | set(data.get("build-dependencies") or {})
    dev = set(data.get("dev-dependencies") or {})
    return {str(n) for n in dev - runtime}


class CargoLockAdapter:
    id = "cargo-lock"

    def matches(self, filename: str, parent_dir: str) -> bool:
        return filename == "Cargo.lock"

    def parse(self, content: str, ctx: ParseContext) -> ParseResult:
        data = load_toml(content)
        packages = [p for p in data.get("package") or [] if isinstance(p, dict)]
        if not packages and "package" not in data:
            raise ParseError("no [[package]] entries: not a Cargo.lock")
        by_name: dict[str, list[str]] = {}
        nodes: dict[str, dict[str, Any]] = {}
        for pkg in packages:
            name, version = pkg.get("name"), pkg.get("version")
            if isinstance(name, str) and isinstance(version, str):
                nid = f"{name} {version}"
                nodes[nid] = pkg
                by_name.setdefault(name, []).append(nid)

        def resolve(dep: object) -> str | None:
            if not isinstance(dep, str):
                return None
            parts = dep.split(" ")
            if len(parts) == 1:
                candidates = by_name.get(parts[0], [])
                return candidates[0] if len(candidates) == 1 else None
            nid = f"{parts[0]} {parts[1]}"
            return nid if nid in nodes else None

        edges = {
            nid: [r for d in pkg.get("dependencies") or [] if (r := resolve(d))]
            for nid, pkg in nodes.items()
        }
        members = [nid for nid, pkg in nodes.items() if "source" not in pkg]
        dev_only = _cargo_dev_only(ctx.read_sibling("Cargo.toml"))
        prod_roots: list[str] = []
        dev_roots: list[str] = []
        for member in members:
            for child in edges[member]:
                name = child.split(" ", 1)[0]
                (dev_roots if name in dev_only else prod_roots).append(child)
        graph = walk_graph(edges, prod_roots, dev_roots, lambda n: n.split(" ", 1)[0])

        result = ParseResult()
        for nid, pkg in nodes.items():
            if nid in members:
                continue
            name, version = nid.split(" ", 1)
            source = str(pkg.get("source", ""))
            reason = None if source.startswith(_CRATES_SOURCES) else "non-registry source"
            info = graph.get(nid)
            result.components.append(
                make_component(
                    "crates.io",
                    name,
                    version,
                    ctx,
                    find_line(content, f'name = "{name}"'),
                    info,
                    direct=info.direct if info else (False if members else None),
                    unresolved_reason=reason,
                )
            )
        return result


# ---------------------------------------------------------------------- Go

_GO_LINE = re.compile(r"^(\S+)\s+(v\S+)(\s*//\s*indirect\b.*)?$")
_GO_REPLACE = re.compile(r"^(\S+)(?:\s+(v\S+))?\s*=>\s*(\S+)(?:\s+(v\S+))?$")


def _go_directives(content: str) -> list[tuple[str, str, int]]:
    """(verb, argument line, line number) for require/replace, block or single form."""
    out: list[tuple[str, str, int]] = []
    block: str | None = None
    for lineno, raw in enumerate(content.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("//"):
            continue
        if block:
            if line == ")":
                block = None
            else:
                out.append((block, line, lineno))
            continue
        verb, _, rest = line.partition(" ")
        rest = rest.strip()
        if verb in ("require", "replace"):
            if rest == "(":
                block = verb
            elif rest:
                out.append((verb, rest, lineno))
        elif verb in ("exclude", "retract", "tool", "ignore", "godebug") and rest == "(":
            block = "skip"
    return [d for d in out if d[0] != "skip"]


class GoModAdapter:
    id = "go-mod"

    def matches(self, filename: str, parent_dir: str) -> bool:
        return filename == "go.mod"

    def parse(self, content: str, ctx: ParseContext) -> ParseResult:
        if not re.search(r"^\s*module\s+\S+", content, re.MULTILINE):
            raise ParseError("no `module` directive: not a go.mod file")
        requires: list[tuple[str, str, bool, int]] = []
        replaces: dict[tuple[str, str | None], tuple[str, str | None]] = {}
        result = ParseResult()
        for verb, line, lineno in _go_directives(content):
            if verb == "require":
                m = _GO_LINE.match(line)
                if m is None:
                    result.problems.append(
                        Problem("invalid_require", f"line {lineno}: unparsable", ctx.rel_path)
                    )
                    continue
                requires.append((m.group(1), m.group(2), m.group(3) is None, lineno))
            else:
                r = _GO_REPLACE.match(line)
                if r:
                    replaces[(r.group(1), r.group(2))] = (r.group(3), r.group(4))
        for required, required_version, direct, lineno in requires:
            module, version = required, required_version
            target = replaces.get((required, required_version)) or replaces.get((required, None))
            reason = None
            if target is not None:
                new_module, new_version = target
                if new_version is None:  # replaced by a local directory
                    reason = f"replaced by local path {clean(new_module, 80)}"
                else:
                    module, version = new_module, new_version
            result.components.append(
                make_component(
                    "Go",
                    module,
                    version,
                    ctx,
                    lineno,
                    direct=direct,
                    unresolved_reason=reason,
                )
            )
        return result


# -------------------------------------------------------------------- PHP

_PLATFORM = re.compile(r"^(php|php-64bit|hhvm|composer(-plugin|-runtime)?-api|ext-.+|lib-.+)$")
_COMPOSER_EXACT = re.compile(r"^v?\d+(\.\d+){0,3}([-.]?(alpha|beta|rc|patch|pl|p)\.?\d*)?$", re.I)


def _composer_version(raw: object) -> tuple[str | None, str | None]:
    """(version, unresolved reason) for a composer.lock `version` value."""
    if not isinstance(raw, str) or not raw:
        return None, "no version recorded"
    if raw.startswith("dev-") or raw.endswith("-dev"):
        return None, f"development branch ({clean(raw, 60)})"
    return raw, None


class ComposerLockAdapter:
    id = "composer-lock"

    def matches(self, filename: str, parent_dir: str) -> bool:
        return filename == "composer.lock"

    def parse(self, content: str, ctx: ParseContext) -> ParseResult:
        data = load_json_object(content)
        nodes: dict[str, tuple[dict[str, Any], Scope]] = {}
        for section, scope in (("packages", Scope.PROD), ("packages-dev", Scope.DEV)):
            for pkg in data.get(section) or []:
                if isinstance(pkg, dict) and isinstance(pkg.get("name"), str):
                    nodes.setdefault(pkg["name"].lower(), (pkg, scope))
        if not nodes and "packages" not in data:
            raise ParseError("no `packages` list: not a composer.lock")
        edges = {
            name: [
                d.lower()
                for d in (pkg.get("require") or {})
                if isinstance(d, str) and d.lower() in nodes
            ]
            for name, (pkg, _scope) in nodes.items()
        }
        prod_roots: list[str] = []
        dev_roots: list[str] = []
        manifest = ctx.read_sibling("composer.json")
        if manifest:
            try:
                root = load_json_object(manifest)
            except ParseError:
                root = {}
            prod_roots = [n.lower() for n in root.get("require") or {} if n.lower() in nodes]
            dev_roots = [n.lower() for n in root.get("require-dev") or {} if n.lower() in nodes]
        graph = walk_graph(edges, prod_roots, dev_roots, lambda n: n)
        has_roots = bool(prod_roots or dev_roots)
        result = ParseResult()
        for name, (pkg, scope) in nodes.items():
            version, reason = _composer_version(pkg.get("version"))
            info = graph.get(name)
            result.components.append(
                make_component(
                    "Packagist",
                    name,
                    version,
                    ctx,
                    find_line(content, f'"name": "{pkg["name"]}"'),
                    info,
                    direct=info.direct if info else (False if has_roots else None),
                    scope=scope,
                    unresolved_reason=reason,
                )
            )
        return result


class ComposerJsonAdapter:
    id = "composer-json"

    def matches(self, filename: str, parent_dir: str) -> bool:
        return filename == "composer.json"

    def parse(self, content: str, ctx: ParseContext) -> ParseResult:
        data = load_json_object(content)
        result = ParseResult()
        for section, scope in (("require", Scope.PROD), ("require-dev", Scope.DEV)):
            block = data.get(section)
            if not isinstance(block, dict):
                continue
            for raw_name, constraint in block.items():
                name = str(raw_name).lower()
                if _PLATFORM.match(name) or "/" not in name:
                    continue
                text = str(constraint).strip()
                exact = _COMPOSER_EXACT.match(text) is not None
                result.components.append(
                    make_component(
                        "Packagist",
                        name,
                        text if exact else None,
                        ctx,
                        find_line(content, f'"{raw_name}"'),
                        direct=True,
                        scope=scope,
                        unresolved_reason=None
                        if exact
                        else f"constraint {clean(text, 60)}; commit composer.lock",
                    )
                )
        if result.components:
            result.problems.append(
                Problem(
                    "no_lockfile",
                    "composer.json without composer.lock: only direct dependencies are visible",
                    ctx.rel_path,
                )
            )
        return result
