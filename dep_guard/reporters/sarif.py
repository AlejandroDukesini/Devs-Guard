"""SARIF 2.1.0 for GitHub code scanning and other SARIF consumers.

- one rule per vulnerability id, with `security-severity` (GitHub uses it to
  bucket alerts) taken from the CVSS score or mapped from the severity;
- one result per (vulnerability, package version), located on the manifest
  line that declares the package;
- ignored findings are emitted with an accepted external suppression, so the
  decision stays visible and auditable instead of disappearing;
- partialFingerprints keep alerts stable across runs.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from dep_guard import __version__
from dep_guard.engine import ScanReport
from dep_guard.models import Finding, FindingStatus, Priority, Severity

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFO_URI = "https://github.com/AlejandroDukesini/Devs-Guard"
_LEVEL = {Priority.P0: "error", Priority.P1: "error", Priority.P2: "warning", Priority.P3: "note"}
_SEVERITY_SCORE = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH: 8.0,
    Severity.MEDIUM: 5.5,
    Severity.LOW: 2.0,
    Severity.UNKNOWN: 5.0,
}


def _security_severity(f: Finding) -> str:
    return f"{f.cvss_score if f.cvss_score is not None else _SEVERITY_SCORE[f.severity]:.1f}"


def _rule(f: Finding) -> dict[str, Any]:
    help_uri = f"https://osv.dev/vulnerability/{f.id}"
    fix = f.fixed_versions[0] if f.fixed_versions else None
    help_text = (
        f"{f.summary}\n\nAliases: {', '.join(f.aliases)}\n"
        + (f"Fixed in: {', '.join(f.fixed_versions)}\n" if fix else "No fixed version published.\n")
        + "\n".join(f.references)
    )
    return {
        "id": f.id,
        "name": f.id,
        "shortDescription": {"text": f.summary[:200]},
        "fullDescription": {"text": f.summary},
        "helpUri": help_uri,
        "help": {"text": help_text},
        "defaultConfiguration": {"level": _LEVEL[f.priority]},
        "properties": {
            "security-severity": _security_severity(f),
            "tags": ["security", "vulnerability", "dependency", *f.cwes],
            "precision": "high",
        },
    }


def _result(f: Finding) -> dict[str, Any]:
    c = f.component
    loc = c.locations[0] if c.locations else None
    fix = (
        f"Upgrade to {f.fixed_versions[0]}." if f.fixed_versions else "No fixed version published."
    )
    via = (
        ""
        if c.direct is not False or not c.paths
        else f" (transitive via {' > '.join(c.paths[0])})"
    )
    message = (
        f"{c.name}@{c.version} is affected by {f.id} [{f.severity.value}, {f.priority.value}]"
        f"{via}: {f.summary} {fix}"
    )
    fingerprint = hashlib.sha256(f"{f.id}|{c.purl}|{c.version}".encode()).hexdigest()
    result: dict[str, Any] = {
        "ruleId": f.id,
        "level": _LEVEL[f.priority],
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": loc.file if loc else "",
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {"startLine": (loc.line if loc and loc.line else 1)},
                }
            }
        ],
        "partialFingerprints": {"depguard/v1": fingerprint},
        "properties": {
            "priority": f.priority.value,
            "package": c.purl_with_version,
            "epss": f.epss,
            "kev": f.kev,
            "reasons": [r.text for r in f.reasons],
        },
    }
    if f.status is FindingStatus.IGNORED:
        result["suppressions"] = [
            {
                "kind": "external",
                "status": "accepted",
                "justification": f"{f.ignore_reason} (expires {f.ignore_expires})",
            }
        ]
    return result


def to_dict(report: ScanReport) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    for f in report.findings:
        rules.setdefault(f.id, _rule(f))
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "DepGuard",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": INFO_URI,
                        "rules": [rules[k] for k in sorted(rules)],
                    }
                },
                "results": [_result(f) for f in report.findings],
                "invocations": [
                    {
                        "executionSuccessful": report.policy.verdict.value != "INCOMPLETE",
                        "toolExecutionNotifications": [
                            {"level": "warning", "message": {"text": f"{p.code}: {p.message}"}}
                            for p in report.problems
                        ],
                    }
                ],
            }
        ],
    }


def render(report: ScanReport) -> str:
    return json.dumps(to_dict(report), indent=2, ensure_ascii=False) + "\n"
