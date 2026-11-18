"""NIST National Vulnerability Database (CVE API 2.0) as a severity fallback.

https://nvd.nist.gov/developers/vulnerabilities

OSV is the source of truth for *whether* a package version is affected. Some
advisories reach OSV without a CVSS vector (only a qualitative label, or
nothing), and OSV CWE data comes only from GitHub advisories. For those
findings, and only those, DepGuard asks NVD for:
- CVSS v3.1 / v3.0 vectors (scored by DepGuard's own calculator, so all
  v3 scores in a report are computed the same way);
- CVSS v4.0 base score as published by NVD (DepGuard does not compute v4);
- CWE identifiers.

Opt-in (`--nvd` / `[sources] nvd = true`). Without an API key NVD allows 5
requests per rolling 30 seconds, so requests are paced and capped per scan;
set NVD_API_KEY to raise the limit (the key is sent only to NVD, as the
`apiKey` header, and never logged). Results are cached for a week.
"""

from __future__ import annotations

import asyncio
import os
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from dep_guard import cvss
from dep_guard.models import Finding, Severity
from dep_guard.sources.cache import Cache
from dep_guard.sources.http import HttpClient, SourceError

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
WEEK = 7 * 24 * 3600
MAX_LOOKUPS = 25
_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_CWE = re.compile(r"^CWE-\d{1,5}$")


@dataclass(frozen=True, slots=True)
class NvdMetrics:
    score: float | None
    vector: str | None
    severity: Severity
    source: str  # "nvd_cvss_v3" | "nvd_cvss_v4" | "nvd_none"
    cwes: tuple[str, ...]


def parse_cve(record: dict[str, Any]) -> NvdMetrics:
    """Extract metrics from one `vulnerabilities[].cve` object."""
    raw_metrics = record.get("metrics")
    metrics: dict[str, Any] = raw_metrics if isinstance(raw_metrics, dict) else {}

    def pick(key: str) -> dict[str, Any] | None:
        rows = [r for r in metrics.get(key) or [] if isinstance(r, dict)]
        primary = [r for r in rows if r.get("type") == "Primary"]
        candidates = primary or rows
        data = candidates[0].get("cvssData") if candidates else None
        return data if isinstance(data, dict) else None

    cwes = tuple(
        sorted(
            {
                str(d.get("value"))
                for w in record.get("weaknesses") or []
                if isinstance(w, dict)
                for d in w.get("description") or []
                if isinstance(d, dict) and _CWE.match(str(d.get("value", "")))
            }
        )
    )
    for key in ("cvssMetricV31", "cvssMetricV30"):
        data = pick(key)
        vector = str(data.get("vectorString", "")) if data else ""
        score = cvss.base_score_v3(vector) if vector else None
        if score is not None:
            return NvdMetrics(score, vector, cvss.severity_from_score(score), "nvd_cvss_v3", cwes)
    data = pick("cvssMetricV40")
    if data and isinstance(data.get("baseScore"), int | float):
        score = float(data["baseScore"])
        if 0.0 <= score <= 10.0:
            v4_vector = str(data.get("vectorString", "")) or None
            return NvdMetrics(
                score, v4_vector, cvss.severity_from_score(score), "nvd_cvss_v4", cwes
            )
    return NvdMetrics(None, None, Severity.UNKNOWN, "nvd_none", cwes)


Sleep = Callable[[float], Awaitable[None]]


class NvdSource:
    def __init__(
        self,
        http: HttpClient | None,
        cache: Cache,
        api_key: str | None = None,
        sleep: Sleep = asyncio.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._http, self._cache = http, cache
        self._key = api_key if api_key is not None else os.environ.get("NVD_API_KEY") or None
        # NVD public limits: 5 requests / 30 s without a key, 50 / 30 s with one.
        self._interval = 0.7 if self._key else 6.5
        self._sleep, self._clock = sleep, clock
        self._last: float | None = None

    async def _paced_get(self, cve: str) -> Any:
        if self._http is None:
            raise SourceError("no HTTP client (offline mode)")
        if self._last is not None:
            wait = self._interval - (self._clock() - self._last)
            if wait > 0:
                await self._sleep(wait)
        self._last = self._clock()
        headers = {"apiKey": self._key} if self._key else None
        return await self._http.get_json(NVD_URL, params={"cveId": cve}, headers=headers)

    async def lookup(self, cves: list[str]) -> tuple[dict[str, NvdMetrics], str | None]:
        """({cve: metrics}, warning or None). Unknown CVEs are simply absent."""
        wanted = sorted({c for c in cves if _CVE.match(c)})
        found: dict[str, NvdMetrics] = {}
        to_fetch: list[str] = []
        for cve in wanted:
            cached = self._cache.get("nvd", cve, WEEK)
            if isinstance(cached, dict):
                found[cve] = _from_cache(cached)
            elif cached == "none":
                continue
            else:
                to_fetch.append(cve)
        warning: str | None = None
        if to_fetch and self._http is None:
            return found, "NVD not available offline for some CVEs"
        if len(to_fetch) > MAX_LOOKUPS:
            warning = (
                f"NVD: only {MAX_LOOKUPS} of {len(to_fetch)} CVEs looked up in this scan "
                "(rate limit); the rest keep the OSV severity"
            )
            to_fetch = to_fetch[:MAX_LOOKUPS]
        for cve in to_fetch:
            try:
                data = await self._paced_get(cve)
            except SourceError as exc:
                return found, f"NVD unavailable: {exc}"
            rows = data.get("vulnerabilities") if isinstance(data, dict) else None
            record = rows[0].get("cve") if isinstance(rows, list) and rows else None
            if not isinstance(record, dict) or record.get("id") != cve:
                self._cache.set("nvd", cve, "none")
                continue
            metrics = parse_cve(record)
            found[cve] = metrics
            self._cache.set(
                "nvd",
                cve,
                {
                    "score": metrics.score,
                    "vector": metrics.vector,
                    "severity": metrics.severity.value,
                    "source": metrics.source,
                    "cwes": list(metrics.cwes),
                },
            )
        return found, warning


def _from_cache(entry: dict[str, Any]) -> NvdMetrics:
    try:
        severity = Severity(str(entry.get("severity")))
    except ValueError:
        severity = Severity.UNKNOWN
    score = entry.get("score")
    return NvdMetrics(
        float(score) if isinstance(score, int | float) else None,
        str(entry["vector"]) if entry.get("vector") else None,
        severity,
        str(entry.get("source", "nvd_none")),
        tuple(str(c) for c in entry.get("cwes") or [] if _CWE.match(str(c))),
    )


def apply(findings: list[Finding], metrics: dict[str, NvdMetrics]) -> int:
    """Fill severity/CWE of findings that OSV left without a CVSS score."""
    updated = 0
    for f in findings:
        if f.cvss_score is not None:
            continue
        best: NvdMetrics | None = None
        for cve in f.cves:
            m = metrics.get(cve)
            if m and m.score is not None and (best is None or m.score > (best.score or 0)):
                best = m
        cwes = {c for cve in f.cves if (m := metrics.get(cve)) for c in m.cwes}
        if cwes - set(f.cwes):
            f.cwes = sorted(set(f.cwes) | cwes)
        if best is not None:
            f.cvss_score, f.cvss_vector = best.score, best.vector
            f.severity, f.severity_source = best.severity, best.source
            updated += 1
    return updated
