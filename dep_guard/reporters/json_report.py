"""Machine-readable report (schema `depguard.report/v1`).

This structure is a contract: the web demo's JavaScript engine produces the
same document, and the shared golden fixtures compare both. Absolute paths
are never included (they leak usernames and machine layout when reports are
shared); every path is relative to the scan root.
"""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

from dep_guard import __version__
from dep_guard.correlate import recommended_upgrade
from dep_guard.engine import ScanReport
from dep_guard.models import Component, ComponentStatus, Finding, FindingStatus, Priority, Severity

SCHEMA = "depguard.report/v1"


def component_dict(c: Component) -> dict[str, Any]:
    return {
        "name": c.name,
        "version": c.version,
        "ecosystem": c.ecosystem,
        "purl": c.purl_with_version,
        "direct": c.direct,
        "scope": c.scope.value,
        "status": c.status.value,
        "unresolved_reason": c.unresolved_reason,
        "error": c.error,
        "paths": c.paths,
        "locations": [{"file": loc.file, "line": loc.line} for loc in c.locations],
    }


def finding_dict(f: Finding) -> dict[str, Any]:
    c = f.component
    return {
        "id": f.id,
        "aliases": f.aliases,
        "summary": f.summary,
        "severity": f.severity.value,
        "cvss": {"score": f.cvss_score, "vector": f.cvss_vector},
        "cwes": f.cwes,
        "package": {
            "name": c.name,
            "version": c.version,
            "ecosystem": c.ecosystem,
            "purl": c.purl_with_version,
            "direct": c.direct,
            "scope": c.scope.value,
            "paths": c.paths,
            "locations": [{"file": loc.file, "line": loc.line} for loc in c.locations],
        },
        "fixed_versions": f.fixed_versions,
        "references": f.references,
        "published": f.published,
        "epss": None if f.epss is None else {"score": f.epss, "percentile": f.epss_percentile},
        "kev": f.kev,
        "priority": f.priority.value,
        "reasons": [{"code": r.code, "text": r.text} for r in f.reasons],
        "status": f.status.value,
        "ignore": (
            {"reason": f.ignore_reason, "expires": f.ignore_expires}
            if f.status is FindingStatus.IGNORED
            else None
        ),
    }


def remediation(findings: list[Finding]) -> list[dict[str, Any]]:
    by_component: dict[str, list[Finding]] = {}
    for f in findings:
        if f.status is FindingStatus.ACTIVE:
            by_component.setdefault(f.component.key, []).append(f)
    out: list[dict[str, Any]] = []
    for group in by_component.values():
        target, fixes = recommended_upgrade(group)
        comp = group[0].component
        out.append(
            {
                "package": comp.name,
                "ecosystem": comp.ecosystem,
                "current": comp.version,
                "upgrade_to": target,
                "fixes": fixes,
                "of": len(group),
                "direct": comp.direct,
                "via": comp.paths[0] if comp.paths else [],
                "top_priority": min(f.priority.rank for f in group),
            }
        )
    out.sort(key=lambda r: (int(r["top_priority"]), -int(r["of"]), str(r["package"])))
    for r in out:
        r["top_priority"] = f"P{r['top_priority']}"
    return out


def summary(report: ScanReport) -> dict[str, Any]:
    active = report.active_findings
    statuses = Counter(c.status for c in report.components)
    return {
        "manifests": len(report.manifests),
        "components": len(report.components),
        "direct": sum(1 for c in report.components if c.direct),
        "vulnerable_components": statuses[ComponentStatus.VULNERABLE],
        "findings": len(active),
        "ignored": len(report.findings) - len(active),
        "by_priority": {p.value: sum(1 for f in active if f.priority is p) for p in Priority},
        "by_severity": {s.value: sum(1 for f in active if f.severity is s) for s in Severity},
        "unresolved": statuses[ComponentStatus.UNRESOLVED],
        "errors": statuses[ComponentStatus.ERROR],
        "private": statuses[ComponentStatus.PRIVATE],
    }


def to_dict(report: ScanReport) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "tool": {"name": "depguard", "version": __version__},
        "generated_at": report.generated_at,
        "verdict": report.policy.verdict.value,
        "exit_code": report.exit_code,
        "summary": summary(report),
        "policy": {
            "violations": report.policy.violations,
            "incomplete_reasons": report.policy.incomplete_reasons,
            "expired_ignores": report.policy.expired_ignores,
            "unused_ignores": report.policy.unused_ignores,
        },
        "sources": report.sources,
        "manifests": [
            {"path": m.path, "adapter": m.adapter, "components": m.components, "error": m.error}
            for m in report.manifests
        ],
        "findings": [finding_dict(f) for f in report.findings],
        "remediation": remediation(report.findings),
        "components": [component_dict(c) for c in report.components],
        "problems": [
            {"code": p.code, "message": p.message, "file": p.file} for p in report.problems
        ],
        "stats": report.stats,
    }


def render(report: ScanReport) -> str:
    return json.dumps(to_dict(report), indent=2, ensure_ascii=False) + "\n"
