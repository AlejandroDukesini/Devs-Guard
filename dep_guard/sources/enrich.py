"""Exploitability signals: FIRST EPSS and CISA KEV.

Both are optional enrichment. If unavailable, findings keep `epss=None` /
`kev=None` (unknown) and the scan reports a warning; vulnerability *status*
is unaffected, because that comes from OSV alone.

- EPSS: https://www.first.org/epss/api  (probability of exploitation in 30 days)
- KEV:  https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""

from __future__ import annotations

import re
from typing import Any

from dep_guard.sources.cache import Cache
from dep_guard.sources.http import HttpClient, SourceError

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DAY = 24 * 3600
EPSS_CHUNK = 100
_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$")


class EpssSource:
    def __init__(self, http: HttpClient | None, cache: Cache, ttl: float = DAY) -> None:
        self._http, self._cache, self._ttl = http, cache, ttl

    async def scores(self, cves: list[str]) -> tuple[dict[str, tuple[float, float]], str | None]:
        """Return ({cve: (epss, percentile)}, error message or None)."""
        wanted = sorted({c for c in cves if _CVE.match(c)})
        found: dict[str, tuple[float, float]] = {}
        missing: list[str] = []
        for cve in wanted:
            cached = self._cache.get("epss", cve, self._ttl)
            if isinstance(cached, list) and len(cached) == 2:
                found[cve] = (float(cached[0]), float(cached[1]))
            elif cached == "none":
                continue  # EPSS has no score for this CVE (cached negative answer)
            else:
                missing.append(cve)
        if not missing:
            return found, None
        if self._http is None:
            return found, "EPSS not available offline for some CVEs"
        try:
            for i in range(0, len(missing), EPSS_CHUNK):
                chunk = missing[i : i + EPSS_CHUNK]
                data = await self._http.get_json(
                    EPSS_URL, params={"cve": ",".join(chunk), "limit": str(EPSS_CHUNK)}
                )
                rows = data.get("data") if isinstance(data, dict) else None
                if not isinstance(rows, list):
                    raise SourceError("EPSS returned an unexpected shape")
                seen = set()
                for row in rows:
                    parsed = _epss_row(row)
                    if parsed:
                        cve, epss, pct = parsed
                        found[cve] = (epss, pct)
                        seen.add(cve)
                        self._cache.set("epss", cve, [epss, pct])
                for cve in set(chunk) - seen:
                    self._cache.set("epss", cve, "none")
        except SourceError as exc:
            return found, f"EPSS unavailable: {exc}"
        return found, None


def _epss_row(row: Any) -> tuple[str, float, float] | None:
    if not isinstance(row, dict) or not isinstance(row.get("cve"), str):
        return None
    try:
        epss, pct = float(row["epss"]), float(row["percentile"])
    except (KeyError, TypeError, ValueError):
        return None
    if not (0.0 <= epss <= 1.0 and 0.0 <= pct <= 1.0):
        return None
    return row["cve"], epss, pct


class KevSource:
    def __init__(self, http: HttpClient | None, cache: Cache, ttl: float = DAY) -> None:
        self._http, self._cache, self._ttl = http, cache, ttl

    async def catalog(self) -> tuple[dict[str, bool] | None, str | None]:
        """Return ({cve: known_ransomware_use}, error) — None catalog = unknown."""
        cached = self._cache.get("kev", "catalog", self._ttl)
        if isinstance(cached, dict):
            return {str(k): bool(v) for k, v in cached.items()}, None
        if self._http is None:
            stale = self._cache.get("kev", "catalog")  # offline: accept any age
            if isinstance(stale, dict):
                return {str(k): bool(v) for k, v in stale.items()}, None
            return None, "CISA KEV not available offline"
        try:
            data = await self._http.get_json(KEV_URL)
        except SourceError as exc:
            return None, f"CISA KEV unavailable: {exc}"
        vulns = data.get("vulnerabilities") if isinstance(data, dict) else None
        if not isinstance(vulns, list):
            return None, "CISA KEV returned an unexpected shape"
        catalog = {
            v["cveID"]: str(v.get("knownRansomwareCampaignUse", "")).lower() == "known"
            for v in vulns
            if isinstance(v, dict) and isinstance(v.get("cveID"), str) and _CVE.match(v["cveID"])
        }
        self._cache.set("kev", "catalog", catalog)
        return catalog, None
