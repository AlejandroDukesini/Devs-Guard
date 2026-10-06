"""Scan orchestration: discover -> parse -> query -> correlate -> enrich -> risk -> policy."""

from __future__ import annotations

import asyncio
import datetime as dt
import fnmatch
import logging
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from dep_guard import __version__, correlate, risk
from dep_guard.adapters import ParseContext, ParseError
from dep_guard.config import Config, ConfigError, find_config, load
from dep_guard.discovery import DiscoveryError, ManifestFile, discover, read_text, sibling_reader
from dep_guard.models import (
    Component,
    ComponentStatus,
    Finding,
    FindingStatus,
    Location,
    Problem,
    Scope,
)
from dep_guard.policy import PolicyResult, Verdict, evaluate
from dep_guard.sources.cache import Cache
from dep_guard.sources.enrich import EpssSource, KevSource
from dep_guard.sources.http import HttpClient, new_client
from dep_guard.sources.osv import OsvSource

log = logging.getLogger("depguard")

EXIT_PASS = 0
EXIT_POLICY_FAIL = 1
EXIT_TOOL_ERROR = 2
EXIT_INCOMPLETE = 3


@dataclass(slots=True)
class ScanOptions:
    config_path: Path | None = None
    offline: bool = False
    use_cache: bool = True
    cache_dir: Path | None = None
    epss: bool | None = None  # None = use config
    kev: bool | None = None
    allow_incomplete: bool = False
    today: dt.date | None = None
    config_overrides: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ManifestSummary:
    path: str
    adapter: str
    components: int
    error: str | None = None


@dataclass(slots=True)
class ScanReport:
    root: str
    config: Config
    manifests: list[ManifestSummary]
    components: list[Component]
    findings: list[Finding]
    problems: list[Problem]
    policy: PolicyResult
    sources: dict[str, str]
    stats: dict[str, Any]
    generated_at: str
    tool_version: str = __version__

    @property
    def active_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.status is FindingStatus.ACTIVE]

    @property
    def exit_code(self) -> int:
        if self.policy.verdict is Verdict.FAIL:
            return EXIT_POLICY_FAIL
        if self.policy.verdict is Verdict.INCOMPLETE:
            return EXIT_INCOMPLETE
        return EXIT_PASS


class ToolError(Exception):
    """Unusable input or configuration (exit code 2)."""


def scan(target: str | Path, options: ScanOptions | None = None) -> ScanReport:
    """Public library entry point."""
    return asyncio.run(scan_async(target, options or ScanOptions()))


async def scan_async(target: str | Path, options: ScanOptions) -> ScanReport:
    started = time.perf_counter()
    timings: dict[str, float] = {}
    today = options.today or dt.date.today()
    try:
        root, files, problems = discover(target)
        config_path = options.config_path or find_config(root)
        config = load(config_path, today)
    except (DiscoveryError, ConfigError) as exc:
        raise ToolError(str(exc)) from None
    config = replace(config, **options.config_overrides) if options.config_overrides else config
    if options.allow_incomplete:
        config.fail_on_incomplete = False
    if config.exclude:  # re-discover honouring config excludes
        root, files, problems = discover(target, config.exclude)
    if not files:
        problems.append(Problem("no_manifests", "no supported manifest or lockfile found", None))

    t0 = time.perf_counter()
    manifests, components, parse_problems, parse_failures = parse_files(files)
    problems += parse_problems
    mark_private(components, config.private_packages)
    timings["parse_ms"] = _ms(t0)

    cache = Cache(options.cache_dir, enabled=options.use_cache)
    sources: dict[str, str] = {}
    use_epss = config.epss if options.epss is None else options.epss
    use_kev = config.kev if options.kev is None else options.kev

    async with new_client(config.timeout) as client:
        http = None if options.offline else HttpClient(client, retries=config.retries)
        findings = await _query_and_correlate(
            components, http, cache, options.offline, sources, problems, timings
        )
        await _enrich(findings, http, cache, use_epss, use_kev, sources, problems, timings)

    t0 = time.perf_counter()
    risk_cfg = risk.RiskConfig(epss_threshold=config.epss_threshold)
    for f in findings:
        risk.assess(f, risk_cfg)
    findings.sort(
        key=lambda f: (
            f.priority.rank,
            -f.severity.rank,
            f.component.name,
            f.component.version or "",
            f.id,
        )
    )
    components.sort(key=lambda c: (c.ecosystem, c.name, c.version or ""))
    policy = evaluate(findings, components, config, today, parse_failures)
    for msg in policy.unused_ignores:
        problems.append(
            Problem("unused_ignore", msg, Path(config.source).name if config.source else None)
        )
    timings["risk_policy_ms"] = _ms(t0)

    timings["total_ms"] = _ms(started)
    stats: dict[str, Any] = {
        **timings,
        "http_requests": http.request_count if http else 0,
        "cache_hits": cache.hits,
        "cache_misses": cache.misses,
    }
    log.info("scan finished in %.0f ms (%d requests)", timings["total_ms"], stats["http_requests"])
    return ScanReport(
        root=str(root),
        config=config,
        manifests=manifests,
        components=components,
        findings=findings,
        problems=problems,
        policy=policy,
        sources=sources,
        stats=stats,
        generated_at=dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat(),
    )


async def _query_and_correlate(
    components: list[Component],
    http: HttpClient | None,
    cache: Cache,
    offline: bool,
    sources: dict[str, str],
    problems: list[Problem],
    timings: dict[str, float],
) -> list[Finding]:
    t0 = time.perf_counter()
    queryable = [
        c
        for c in components
        if c.version and c.status not in (ComponentStatus.PRIVATE, ComponentStatus.UNRESOLVED)
    ]
    osv = OsvSource(http, cache, offline=offline)
    outcome = await osv.query(queryable)
    wanted: dict[str, str] = {}
    for comp in queryable:
        if comp.key in outcome.errors:
            comp.status = ComponentStatus.ERROR
            comp.error = outcome.errors[comp.key]
            continue
        ids = outcome.ids.get(comp.key, [])
        comp.status = ComponentStatus.VULNERABLE if ids else ComponentStatus.CLEAN
        for vid, modified in ids:
            wanted[vid] = max(wanted.get(vid, ""), modified)
    timings["osv_query_ms"] = _ms(t0)

    t0 = time.perf_counter()
    records, detail_errors = await osv.fetch(wanted)
    timings["osv_details_ms"] = _ms(t0)
    if detail_errors:
        problems.append(
            Problem(
                "advisory_details_unavailable",
                f"details unavailable for {len(detail_errors)} advisories; "
                "shown as UNKNOWN severity",
                None,
            )
        )
    errored = sum(1 for c in queryable if c.status is ComponentStatus.ERROR)
    if errored:
        reasons = sorted({c.error or "" for c in queryable if c.status is ComponentStatus.ERROR})
        sources["osv"] = f"error: {errored} dependencies not checked ({'; '.join(reasons)[:300]})"
    else:
        sources["osv"] = "offline-cache" if offline else "ok"

    findings: list[Finding] = []
    for comp in queryable:
        if comp.status is ComponentStatus.VULNERABLE:
            advisory_ids = [vid for vid, _ in outcome.ids[comp.key]]
            findings += correlate.build_findings(comp, advisory_ids, records)
    return findings


async def _enrich(
    findings: list[Finding],
    http: HttpClient | None,
    cache: Cache,
    use_epss: bool,
    use_kev: bool,
    sources: dict[str, str],
    problems: list[Problem],
    timings: dict[str, float],
) -> None:
    t0 = time.perf_counter()
    cves = sorted({c for f in findings for c in f.cves})
    if not use_epss:
        sources["epss"] = "disabled"
    elif cves:
        scores, err = await EpssSource(http, cache).scores(cves)
        for f in findings:
            best = max((scores[c] for c in f.cves if c in scores), default=None)
            if best:
                f.epss, f.epss_percentile = best
        sources["epss"] = f"error: {err}" if err else "ok"
        if err:
            problems.append(Problem("epss_unavailable", err, None))
    else:
        sources["epss"] = "not needed"

    if not use_kev:
        sources["kev"] = "disabled"
    elif findings:
        catalog, err = await KevSource(http, cache).catalog()
        if catalog is not None:
            for f in findings:
                f.kev = any(c in catalog for c in f.cves)
        sources["kev"] = f"error: {err}" if err else "ok"
        if err:
            problems.append(Problem("kev_unavailable", err, None))
    else:
        sources["kev"] = "not needed"
    timings["enrich_ms"] = _ms(t0)


def parse_files(
    files: list[ManifestFile],
) -> tuple[list[ManifestSummary], list[Component], list[Problem], int]:
    manifests: list[ManifestSummary] = []
    parsed: list[Component] = []
    problems: list[Problem] = []
    failures = 0
    for mf in files:
        try:
            content = read_text(mf.path)
            result = mf.adapter.parse(content, ParseContext(mf.rel_path, sibling_reader(mf.path)))
        except (ParseError, DiscoveryError, OSError) as exc:
            failures += 1
            message = (exc.strerror or "read error") if isinstance(exc, OSError) else str(exc)
            manifests.append(ManifestSummary(mf.rel_path, mf.adapter.id, 0, message))
            problems.append(Problem("parse_error", message, mf.rel_path))
            continue
        manifests.append(ManifestSummary(mf.rel_path, mf.adapter.id, len(result.components)))
        parsed += result.components
        problems += result.problems
    return manifests, merge_components(parsed), problems, failures


def collect(target: str | Path) -> tuple[Path, list[Component], list[Problem]]:
    """Discover and parse only (no network): used by `depguard sbom`."""
    try:
        root, files, problems = discover(target)
        config = load(find_config(root))
        if config.exclude:
            root, files, problems = discover(target, config.exclude)
    except (DiscoveryError, ConfigError) as exc:
        raise ToolError(str(exc)) from None
    _, components, parse_problems, failures = parse_files(files)
    if failures:
        raise ToolError(
            "; ".join(f"{p.file}: {p.message}" for p in parse_problems if p.code == "parse_error")
        )
    components.sort(key=lambda c: (c.ecosystem, c.name, c.version or ""))
    return root, components, problems + parse_problems


def merge_components(components: list[Component]) -> list[Component]:
    merged: dict[str, Component] = {}
    for comp in components:
        existing = merged.get(comp.key)
        if existing is None:
            merged[comp.key] = comp
            continue
        existing.locations = _unique(existing.locations + comp.locations)
        existing.paths = [
            list(p) for p in _unique([tuple(p) for p in existing.paths + comp.paths])
        ][:3]
        if True in (existing.direct, comp.direct):
            existing.direct = True
        elif False in (existing.direct, comp.direct):
            existing.direct = False
        rank = {Scope.PROD: 0, Scope.UNKNOWN: 1, Scope.DEV: 2}
        if rank[comp.scope] < rank[existing.scope]:
            existing.scope = comp.scope
        existing.unresolved_reason = existing.unresolved_reason or comp.unresolved_reason
    return list(merged.values())


def mark_private(components: list[Component], patterns: list[str]) -> None:
    if not patterns:
        return
    for comp in components:
        if any(fnmatch.fnmatchcase(comp.name, p) for p in patterns):
            comp.status = ComponentStatus.PRIVATE


def _unique(items: list[Any]) -> list[Any]:
    seen: list[Any] = []
    for item in items:
        if item not in seen:
            seen.append(item)
    return seen


def _ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 1)


__all__ = [
    "EXIT_INCOMPLETE",
    "EXIT_PASS",
    "EXIT_POLICY_FAIL",
    "EXIT_TOOL_ERROR",
    "Location",
    "ScanOptions",
    "ScanReport",
    "ToolError",
    "collect",
    "scan",
    "scan_async",
]
