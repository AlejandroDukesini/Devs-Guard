"""CycloneDX JSON SBOM input.

This is how DepGuard covers ecosystems it has no native parser for: generate
an SBOM with a dedicated tool (Syft, cdxgen, the CycloneDX plugins for
Maven/Gradle...) and scan it. Components are identified by purl only.
"""

from __future__ import annotations

import json
from typing import Any

from dep_guard import purl
from dep_guard.adapters.base import ParseContext, ParseError, ParseResult, location, walk_graph
from dep_guard.models import Component, ComponentStatus, Problem, Scope
from dep_guard.textutil import clean, find_line

_MAX_NESTING = 10


class CycloneDxAdapter:
    id = "cyclonedx-json"

    def matches(self, filename: str, parent_dir: str) -> bool:
        lower = filename.lower()
        return lower.endswith((".cdx.json", ".bom.json")) or lower in ("bom.json", "sbom.json")

    def parse(self, content: str, ctx: ParseContext) -> ParseResult:
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ParseError(f"invalid JSON at line {exc.lineno}") from None
        if not isinstance(data, dict) or data.get("bomFormat") != "CycloneDX":
            raise ParseError("not a CycloneDX JSON document (bomFormat != CycloneDX)")

        result = ParseResult()
        flat: list[dict[str, Any]] = []
        _flatten(data.get("components"), flat, 0)

        nodes: dict[str, dict[str, Any]] = {}
        for comp in flat:
            ref = comp.get("bom-ref") or comp.get("purl")
            if isinstance(ref, str):
                nodes[ref] = comp

        edges: dict[str, list[str]] = {}
        for dep in data.get("dependencies") or []:
            if isinstance(dep, dict) and isinstance(dep.get("ref"), str):
                edges[dep["ref"]] = [d for d in dep.get("dependsOn") or [] if isinstance(d, str)]

        metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
        root_comp = metadata.get("component") if isinstance(metadata, dict) else None
        root_ref = root_comp.get("bom-ref") if isinstance(root_comp, dict) else None
        has_graph = bool(edges) and isinstance(root_ref, str) and root_ref in edges
        graph = (
            walk_graph(edges, edges[root_ref], [], lambda r: _label(nodes.get(r), r))
            if has_graph and isinstance(root_ref, str)
            else {}
        )

        skipped_types: set[str] = set()
        for ref, comp in nodes.items():
            parsed = purl.parse(comp.get("purl", ""))
            if parsed is None:
                result.problems.append(
                    Problem(
                        "missing_purl",
                        f"component {clean(ref, 80)} has no valid purl",
                        ctx.rel_path,
                    )
                )
                continue
            ecosystem = parsed.ecosystem
            if ecosystem is None:
                skipped_types.add(parsed.type)
                continue
            info = graph.get(ref)
            scope = Scope.DEV if comp.get("scope") == "excluded" else Scope.PROD
            component = Component(
                ecosystem=ecosystem,
                name=clean(parsed.osv_name, 300),
                version=parsed.version,
                purl=purl.build(ecosystem, parsed.osv_name),
                direct=info.direct if info else (False if has_graph else None),
                scope=scope,
                locations=location(ctx, find_line(content, json.dumps(comp.get("purl")))),
                paths=[info.path] if info else [],
            )
            if component.version is None:
                component.status = ComponentStatus.UNRESOLVED
                component.unresolved_reason = "purl has no version"
            result.components.append(component)

        if skipped_types:
            result.problems.append(
                Problem(
                    "unsupported_purl_types",
                    "components skipped, purl types not supported: "
                    + ", ".join(sorted(skipped_types)),
                    ctx.rel_path,
                )
            )
        return result


def _flatten(items: object, out: list[dict[str, Any]], depth: int) -> None:
    if not isinstance(items, list) or depth > _MAX_NESTING:
        return
    for item in items:
        if isinstance(item, dict):
            out.append(item)
            _flatten(item.get("components"), out, depth + 1)


def _label(comp: dict[str, Any] | None, ref: str) -> str:
    if comp:
        parsed = purl.parse(comp.get("purl", ""))
        if parsed:
            return clean(parsed.osv_name, 120)
        if isinstance(comp.get("name"), str):
            return clean(comp["name"], 120)
    return clean(ref, 120)
