"""JavaScript lockfiles beyond npm: pnpm-lock.yaml and yarn.lock.

pnpm-lock.yaml
  lockfileVersion 5.x keys packages as `/name/1.2.3`, 6.x as `/name@1.2.3`,
  9.x as `name@1.2.3` with dependency edges in a separate `snapshots` map.
  Keys and references may carry peer suffixes, `(react@18.2.0)` (6+) or
  `_react@18.2.0` (5), which do not change the installed version. Direct
  dependencies come from `importers` (one per workspace project) or, in
  single-project 5/6 lockfiles, from the top-level dependency sections.

yarn.lock
  Yarn 1 uses its own line format; Yarn 2+ (Berry) writes YAML with a
  `__metadata` entry. In both, an entry is keyed by every `name@range`
  selector that resolved to it. Yarn 1 does not record direct dependencies,
  so the sibling package.json provides them when present.
"""

from __future__ import annotations

from typing import Any

from dep_guard.adapters.base import (
    GraphInfo,
    ParseContext,
    ParseError,
    ParseResult,
    make_component,
    walk_graph,
)
from dep_guard.adapters.safe_formats import load_json_object, load_yaml_mapping
from dep_guard.models import Component, Location, Problem, Scope
from dep_guard.textutil import clean, find_line
from dep_guard.versions import is_semver

_ROOT_FIELDS = (
    ("dependencies", Scope.PROD),
    ("optionalDependencies", Scope.PROD),
    ("devDependencies", Scope.DEV),
)
_NON_REGISTRY = ("file:", "link:", "workspace:", "portal:", "git", "github:", "http", "patch:")


def _split_at(spec: str) -> tuple[str, str] | None:
    """ "@scope/name@1.2.3" -> ("@scope/name", "1.2.3").

    The name ends at the first "@" after position 0 (only a scope may start
    with "@"); versions and ranges may contain "@" themselves
    (`patch:typescript@npm%3A5.0.4`, `git+ssh://git@host/...`).
    """
    at = spec.find("@", 1)
    if at <= 0:
        return None
    return spec[:at], spec[at + 1 :]


def _npm_component(
    name: str,
    version: str,
    ctx: ParseContext,
    content: str,
    needle: str,
    info: GraphInfo | None,
    scope: Scope | None = None,
    non_registry: bool = False,
) -> Component:
    reason = None
    if non_registry:
        reason = "non-registry source"
    elif not is_semver(version):
        reason = f"not a registry version ({clean(version, 60)})"
    return make_component(
        "npm",
        name,
        version,
        ctx,
        find_line(content, needle),
        info,
        direct=info.direct if info else False,
        scope=scope,
        unresolved_reason=reason,
    )


# --------------------------------------------------------------------- pnpm


class PnpmLockAdapter:
    id = "pnpm-lock"

    def matches(self, filename: str, parent_dir: str) -> bool:
        return filename == "pnpm-lock.yaml"

    def parse(self, content: str, ctx: ParseContext) -> ParseResult:
        data = load_yaml_mapping(content)
        raw_version = str(data.get("lockfileVersion", ""))
        major_text = raw_version.split(".", 1)[0]
        if not major_text.isdigit() or int(major_text) < 5:
            raise ParseError(
                f"unsupported pnpm lockfileVersion {clean(raw_version, 10)}; "
                "regenerate it with pnpm >= 7"
            )
        v5 = int(major_text) == 5

        def node_id(key: str) -> tuple[str, str] | None:
            key = key.lstrip("/").split("(", 1)[0]
            if v5:
                name, _, version = key.rpartition("/")
                version = version.split("_", 1)[0]
                return (name, version) if name and version else None
            return _split_at(key)

        def ref_id(dep_name: str, ref: object) -> str | None:
            if isinstance(ref, dict):  # v6+ importer entries: {specifier, version}
                ref = ref.get("version")
            if not isinstance(ref, str) or ref.startswith(("link:", "file:")):
                return None
            ref = ref.split("(", 1)[0]
            if v5:
                ref = ref.split("_", 1)[0]
            if ref.startswith("/") or (not ref[:1].isdigit() and "@" in ref[1:]):
                parsed = node_id(ref)  # alias: the reference is a full package key
                return f"{parsed[0]}@{parsed[1]}" if parsed else None
            return f"{dep_name}@{ref}"

        packages = data.get("packages") or {}
        snapshots = data.get("snapshots") or {}
        if not isinstance(packages, dict) or not isinstance(snapshots, dict):
            raise ParseError("pnpm lockfile `packages`/`snapshots` is not a mapping")

        nodes: dict[str, tuple[str, str, dict[str, Any], str]] = {}
        for key, entry in packages.items():
            parsed = node_id(str(key))
            if parsed is None or not isinstance(entry, dict):
                continue
            nid = f"{parsed[0]}@{parsed[1]}"
            nodes.setdefault(nid, (parsed[0], parsed[1], entry, str(key)))

        edges: dict[str, list[str]] = {}
        for key, entry in (snapshots or packages).items():
            parsed = node_id(str(key))
            if parsed is None or not isinstance(entry, dict):
                continue
            nid = f"{parsed[0]}@{parsed[1]}"
            children = edges.setdefault(nid, [])
            for field in ("dependencies", "optionalDependencies"):
                deps = entry.get(field)
                if isinstance(deps, dict):
                    children += [c for n, r in deps.items() if (c := ref_id(str(n), r))]

        importers = data.get("importers")
        if not isinstance(importers, dict):
            importers = {".": data}
        prod_roots: list[str] = []
        dev_roots: list[str] = []
        for importer in importers.values():
            if not isinstance(importer, dict):
                continue
            for field, scope in _ROOT_FIELDS:
                section = importer.get(field)
                if not isinstance(section, dict):
                    continue
                for dep_name, ref in section.items():
                    rid = ref_id(str(dep_name), ref)
                    if rid:
                        (dev_roots if scope is Scope.DEV else prod_roots).append(rid)

        graph = walk_graph(edges, prod_roots, dev_roots, lambda n: n.rsplit("@", 1)[0])
        result = ParseResult()
        for nid, (name, version, entry, key) in nodes.items():
            dev_flag = entry.get("dev")
            pkg_scope: Scope | None = (
                Scope.DEV if dev_flag is True else Scope.PROD if dev_flag is False else None
            )
            resolution = entry.get("resolution")
            non_registry = isinstance(resolution, dict) and (
                "directory" in resolution
                or "repo" in resolution
                or resolution.get("type") == "git"
                or ("tarball" in resolution and "integrity" not in resolution)
            )
            result.components.append(
                _npm_component(
                    name, version, ctx, content, key, graph.get(nid), pkg_scope, non_registry
                )
            )
        return result


# --------------------------------------------------------------------- yarn


def _unquote(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] == '"':
        return text[1:-1]
    return text


def _parse_yarn_v1(content: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    block: str | None = None
    for lineno, raw in enumerate(content.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if indent == 0:
            if not stripped.endswith(":"):
                raise ParseError(f"line {lineno}: unexpected content in yarn.lock")
            current = {
                "selectors": [_unquote(s) for s in stripped[:-1].split(",") if s.strip()],
                "deps": {},
                "line": lineno,
            }
            entries.append(current)
            block = None
            continue
        if current is None:
            raise ParseError(f"line {lineno}: indented line before the first entry")
        if indent == 2:
            if stripped.endswith(":"):
                block = stripped[:-1]
                continue
            block = None
            key, _, value = stripped.partition(" ")
            current[_unquote(key)] = _unquote(value)
        elif block in ("dependencies", "optionalDependencies"):
            key, _, value = stripped.partition(" ")
            current["deps"][_unquote(key)] = _unquote(value)
    return entries


def _parse_yarn_berry(data: dict[str, Any]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for key, value in data.items():
        if key == "__metadata" or not isinstance(value, dict):
            continue
        deps: dict[str, str] = {}
        for field in ("dependencies", "optionalDependencies"):
            section = value.get(field)
            if isinstance(section, dict):
                deps.update({str(k): str(v) for k, v in section.items()})
        entries.append(
            {
                "selectors": [s.strip() for s in str(key).split(",") if s.strip()],
                "deps": deps,
                "version": str(value.get("version", "")),
                "resolution": str(value.get("resolution", "")),
                "line": None,
            }
        )
    return entries


def _manifest_roots(package_json: str | None) -> tuple[dict[str, str], dict[str, str]]:
    """Direct dependencies {name: range} from a sibling package.json."""
    if not package_json:
        return {}, {}
    try:
        data = load_json_object(package_json)
    except ParseError:
        return {}, {}
    prod: dict[str, str] = {}
    dev: dict[str, str] = {}
    for field, scope in _ROOT_FIELDS:
        section = data.get(field)
        if isinstance(section, dict):
            target = dev if scope is Scope.DEV else prod
            target.update({str(k): str(v) for k, v in section.items() if isinstance(v, str)})
    return prod, dev


class YarnLockAdapter:
    id = "yarn-lock"

    def matches(self, filename: str, parent_dir: str) -> bool:
        return filename == "yarn.lock"

    def parse(self, content: str, ctx: ParseContext) -> ParseResult:
        berry = "__metadata:" in content
        entries = (
            _parse_yarn_berry(load_yaml_mapping(content)) if berry else _parse_yarn_v1(content)
        )
        by_selector: dict[str, int] = {}
        for idx, entry in enumerate(entries):
            for selector in entry["selectors"]:
                by_selector[selector] = idx

        def lookup(name: str, rng: str) -> int | None:
            for candidate in (f"{name}@{rng}", f"{name}@npm:{rng}"):
                if candidate in by_selector:
                    return by_selector[candidate]
            return None

        workspace_ids = {
            idx for idx, e in enumerate(entries) if "@workspace:" in str(e.get("resolution", ""))
        }
        edges: dict[str, list[str]] = {}
        for idx, entry in enumerate(entries):
            edges[str(idx)] = [
                str(t) for n, r in entry["deps"].items() if (t := lookup(n, r)) is not None
            ]

        prod_ranges, dev_ranges = _manifest_roots(ctx.read_sibling("package.json"))
        prod_roots = [str(t) for n, r in prod_ranges.items() if (t := lookup(n, r)) is not None]
        dev_roots = [str(t) for n, r in dev_ranges.items() if (t := lookup(n, r)) is not None]
        if not prod_roots and not dev_roots:
            # Berry records workspace dependencies in the lockfile itself.
            for ws in sorted(workspace_ids):
                prod_roots += edges[str(ws)]

        def label(node: str) -> str:
            first_selector = entries[int(node)]["selectors"][0]
            split = _split_at(first_selector)
            return split[0] if split else first_selector

        graph = walk_graph(edges, prod_roots, dev_roots, label)
        result = ParseResult()
        if not berry and not (prod_ranges or dev_ranges):
            result.problems.append(
                Problem(
                    "no_direct_info",
                    "yarn.lock without a sibling package.json: direct vs transitive is unknown",
                    ctx.rel_path,
                )
            )
        for idx, entry in enumerate(entries):
            if idx in workspace_ids or not entry["selectors"]:
                continue
            split = _split_at(entry["selectors"][0])
            if split is None:
                continue
            name, rng = split
            version = str(entry.get("version", ""))
            resolution = str(entry.get("resolution", ""))
            if berry:
                non_registry = not (resolution.startswith(f"{name}@npm:") or "npm%3A" in resolution)
            else:
                resolved = str(entry.get("resolved", ""))
                non_registry = rng.startswith(_NON_REGISTRY) or (
                    bool(resolved) and not resolved.startswith("https://")
                )
            info = graph.get(str(idx))
            comp = _npm_component(
                name, version, ctx, content, entry["selectors"][0], info, None, non_registry
            )
            if not info and not (prod_ranges or dev_ranges or workspace_ids):
                comp.direct = None
            if entry.get("line"):
                comp.locations = [Location(ctx.rel_path, entry["line"])]
            result.components.append(comp)
        return result
