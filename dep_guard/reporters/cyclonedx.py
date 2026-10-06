"""CycloneDX 1.6 JSON: SBOM of the scanned project, optionally with vulnerabilities.

`depguard sbom` emits components + dependency graph only (no network).
`depguard scan --format cyclonedx` adds the vulnerabilities section, where
ignored findings carry an `analysis` (VEX) with the documented reason.
The output can be fed back into `depguard scan bom.cdx.json`.
"""

from __future__ import annotations

import itertools
import json
import uuid
from pathlib import PurePath
from typing import Any
from urllib.parse import quote

from dep_guard import __version__
from dep_guard.models import Component, Finding, FindingStatus, Scope

SPEC_VERSION = "1.6"


def full_purl(c: Component) -> str:
    return f"{c.purl}@{quote(c.version, safe='.+-_~')}" if c.version else c.purl


_ref = full_purl  # the versioned purl is unique per component, so it doubles as bom-ref


def _component(c: Component) -> dict[str, Any]:
    out: dict[str, Any] = {
        "type": "library",
        "bom-ref": _ref(c),
        "name": c.name,
        "purl": full_purl(c),
        "scope": "excluded" if c.scope is Scope.DEV else "required",
    }
    if c.version:
        out["version"] = c.version
    return out


def _dependencies(components: list[Component], root_ref: str) -> list[dict[str, Any]]:
    """Root -> direct deps, plus edges recoverable from the recorded paths.

    Paths are name-based; an edge is only emitted when a name maps to exactly
    one component, so no edge is invented between ambiguous versions.
    """
    by_name: dict[str, list[Component]] = {}
    for c in components:
        by_name.setdefault(c.name, []).append(c)
    edges: dict[str, set[str]] = {root_ref: set()}
    for c in components:
        edges.setdefault(_ref(c), set())
        if c.direct:
            edges[root_ref].add(_ref(c))
        for path in c.paths:
            for parent, child in itertools.pairwise(path):
                p, ch = by_name.get(parent, []), by_name.get(child, [])
                if len(p) == 1 and len(ch) == 1:
                    edges.setdefault(_ref(p[0]), set()).add(_ref(ch[0]))
    return [{"ref": ref, "dependsOn": sorted(deps)} for ref, deps in sorted(edges.items())]


def _vulnerability(f: Finding) -> dict[str, Any]:
    v: dict[str, Any] = {
        "bom-ref": f"{f.id}|{_ref(f.component)}",
        "id": f.id,
        "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{f.id}"},
        "references": [
            {"id": a, "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{a}"}}
            for a in f.aliases
            if a != f.id
        ],
        "ratings": [
            {"severity": f.severity.value.lower() if f.severity.value != "UNKNOWN" else "unknown"}
        ],
        "cwes": [int(c.split("-", 1)[1]) for c in f.cwes if c.split("-", 1)[1].isdigit()],
        "description": f.summary,
        "affects": [{"ref": _ref(f.component)}],
        "properties": [
            {"name": "depguard:priority", "value": f.priority.value},
            {"name": "depguard:reasons", "value": " | ".join(r.text for r in f.reasons)},
        ],
    }
    if f.cvss_score is not None:
        v["ratings"] = [
            {
                "source": {"name": "OSV"},
                "score": f.cvss_score,
                "severity": f.severity.value.lower(),
                "method": "CVSSv31" if (f.cvss_vector or "").startswith("CVSS:3.1") else "CVSSv3",
                "vector": f.cvss_vector,
            }
        ]
    if f.fixed_versions:
        v["recommendation"] = f"Upgrade {f.component.name} to {f.fixed_versions[0]} or later."
    if f.published:
        v["published"] = f.published
    if f.status is FindingStatus.IGNORED:
        v["analysis"] = {
            "state": "in_triage",
            "detail": f"{f.ignore_reason} (exception expires {f.ignore_expires})",
        }
    return v


def to_dict(
    components: list[Component],
    root_name: str,
    findings: list[Finding] | None = None,
    timestamp: str | None = None,
) -> dict[str, Any]:
    root_ref = "depguard:root"
    bom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "tools": {
                "components": [{"type": "application", "name": "depguard", "version": __version__}]
            },
            "component": {"type": "application", "bom-ref": root_ref, "name": root_name},
        },
        "components": [_component(c) for c in components if c.version],
        "dependencies": _dependencies([c for c in components if c.version], root_ref),
    }
    if timestamp:
        bom["metadata"]["timestamp"] = timestamp
    if findings is not None:
        bom["vulnerabilities"] = [_vulnerability(f) for f in findings]
    return bom


def render(
    components: list[Component], root: str, findings: list[Finding] | None, timestamp: str | None
) -> str:
    doc = to_dict(components, PurePath(root).name or "project", findings, timestamp)
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
