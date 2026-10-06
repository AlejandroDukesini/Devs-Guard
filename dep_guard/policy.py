"""Policy evaluation: ignores first, then deterministic PASS / FAIL / INCOMPLETE."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from enum import StrEnum

from dep_guard import purl
from dep_guard.config import Config, IgnoreRule
from dep_guard.models import Component, ComponentStatus, Finding, FindingStatus, Reason, Scope


class Verdict(StrEnum):
    PASS = "PASS"  # verdict label, not a password  # noqa: S105  # nosec B105
    FAIL = "FAIL"
    INCOMPLETE = "INCOMPLETE"


@dataclass(slots=True)
class PolicyResult:
    verdict: Verdict
    violations: list[str] = field(default_factory=list)
    incomplete_reasons: list[str] = field(default_factory=list)
    expired_ignores: list[str] = field(default_factory=list)
    unused_ignores: list[str] = field(default_factory=list)


def _matches(rule: IgnoreRule, finding: Finding) -> bool:
    comp = finding.component
    if rule.id and rule.id.upper() not in {a.upper() for a in finding.aliases}:
        return False
    if rule.package:
        return package_matches(rule.package, comp)
    return True


def package_matches(wanted: str, comp: Component) -> bool:
    """`wanted` is a package name or a purl (version, if any, is ignored)."""
    if wanted.startswith("pkg:"):
        parsed = purl.parse(wanted)
        if parsed is None or parsed.ecosystem != comp.ecosystem:
            return False
        return purl.build(parsed.ecosystem, parsed.osv_name) == comp.purl
    name = purl.normalize_pypi_name(wanted) if comp.ecosystem == "PyPI" else wanted
    return name == comp.name


def apply_ignores(findings: list[Finding], rules: list[IgnoreRule], today: dt.date) -> PolicyResult:
    result = PolicyResult(Verdict.PASS)
    used: set[int] = set()
    expired_seen: set[int] = set()
    for finding in findings:
        for rule in rules:
            if not _matches(rule, finding):
                continue
            used.add(rule.index)
            if rule.expires < today:
                expired_seen.add(rule.index)
                finding.reasons.append(
                    Reason("ignore_expired", f"Excepción caducada el {rule.expires.isoformat()}")
                )
                continue
            finding.status = FindingStatus.IGNORED
            finding.ignore_reason = rule.reason
            finding.ignore_expires = rule.expires.isoformat()
            break
    for rule in rules:
        if rule.index in expired_seen:
            result.expired_ignores.append(
                f"{rule.describe()} expired on {rule.expires.isoformat()}"
            )
        if rule.index not in used:
            result.unused_ignores.append(f"{rule.describe()} matched no finding")
    return result


def evaluate(
    findings: list[Finding],
    components: list[Component],
    config: Config,
    today: dt.date,
    parse_failures: int = 0,
) -> PolicyResult:
    result = apply_ignores(findings, config.ignores, today)

    for f in findings:
        if f.status is FindingStatus.IGNORED:
            continue
        if not config.include_dev and f.component.scope is Scope.DEV:
            continue
        label = f"{f.id} in {f.component.name}@{f.component.version}"
        if config.fail_on_priority and f.priority.rank <= config.fail_on_priority.rank:
            result.violations.append(
                f"{label}: priority {f.priority} (limit {config.fail_on_priority})"
            )
        elif config.fail_on_severity and f.severity.rank >= config.fail_on_severity.rank:
            result.violations.append(
                f"{label}: severity {f.severity} (limit {config.fail_on_severity})"
            )
        elif config.fail_on_kev and f.kev:
            result.violations.append(f"{label}: listed in CISA KEV")

    if config.fail_on_expired_ignore:
        result.violations += result.expired_ignores
    unresolved = [c for c in components if c.status is ComponentStatus.UNRESOLVED]
    if config.fail_on_unresolved and unresolved:
        result.violations.append(f"{len(unresolved)} dependencies without an exact version")

    errors = [c for c in components if c.status is ComponentStatus.ERROR]
    if errors:
        result.incomplete_reasons.append(f"{len(errors)} dependencies could not be checked")
    if parse_failures:
        result.incomplete_reasons.append(f"{parse_failures} manifest files could not be parsed")

    if result.violations:
        result.verdict = Verdict.FAIL
    elif result.incomplete_reasons and config.fail_on_incomplete:
        result.verdict = Verdict.INCOMPLETE
    return result
