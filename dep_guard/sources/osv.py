"""OSV.dev client: https://google.github.io/osv.dev/api/

Two phases, as recommended by OSV for scanners:
1. POST /v1/querybatch with every (package, exact version): returns advisory
   ids + `modified` timestamps per component (paginated per query).
2. GET /v1/vulns/{id} for each unique id, cached by `id@modified`.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Any

from dep_guard.models import Component
from dep_guard.sources.cache import Cache
from dep_guard.sources.http import HttpClient, SourceError

log = logging.getLogger("depguard.osv")

BATCH_URL = "https://api.osv.dev/v1/querybatch"
VULN_URL = "https://api.osv.dev/v1/vulns/{}"
BATCH_SIZE = 1000
MAX_PAGES = 20
DETAIL_CONCURRENCY = 10
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{1,100}$")


@dataclass(slots=True)
class QueryOutcome:
    ids: dict[str, list[tuple[str, str]]] = field(
        default_factory=dict
    )  # component.key -> [(id, modified)]
    errors: dict[str, str] = field(default_factory=dict)  # component.key -> reason


class OsvSource:
    def __init__(self, http: HttpClient | None, cache: Cache, offline: bool = False) -> None:
        self._http = http
        self._cache = cache
        self._offline = offline

    @staticmethod
    def _query(comp: Component, page_token: str | None = None) -> dict[str, Any]:
        q: dict[str, Any] = {
            "package": {"name": comp.name, "ecosystem": comp.ecosystem},
            "version": comp.version,
        }
        if page_token:
            q["page_token"] = page_token
        return q

    async def query(self, components: list[Component]) -> QueryOutcome:
        outcome = QueryOutcome()
        if self._offline or self._http is None:
            for comp in components:
                cached = self._cache.get("osv-query", comp.key)
                if isinstance(cached, list):
                    outcome.ids[comp.key] = [(str(i), str(m)) for i, m in cached]
                else:
                    outcome.errors[comp.key] = "not available in offline cache"
            return outcome

        for start in range(0, len(components), BATCH_SIZE):
            chunk = components[start : start + BATCH_SIZE]
            try:
                await self._query_chunk(chunk, outcome)
            except SourceError as exc:
                for comp in chunk:
                    outcome.errors.setdefault(comp.key, str(exc))
        return outcome

    async def _query_chunk(self, chunk: list[Component], outcome: QueryOutcome) -> None:
        if self._http is None:
            raise SourceError("no HTTP client (offline mode)")
        data = await self._http.post_json(BATCH_URL, {"queries": [self._query(c) for c in chunk]})
        results = data.get("results") if isinstance(data, dict) else None
        if not isinstance(results, list) or len(results) != len(chunk):
            raise SourceError("OSV querybatch returned an unexpected shape")

        for comp, result in zip(chunk, results, strict=True):
            try:
                ids = _parse_vulns(result)
                token = result.get("next_page_token") if isinstance(result, dict) else None
                pages = 0
                while token and pages < MAX_PAGES:
                    page = await self._http.post_json(
                        BATCH_URL, {"queries": [self._query(comp, token)]}
                    )
                    page_results = page.get("results") if isinstance(page, dict) else None
                    if not isinstance(page_results, list) or len(page_results) != 1:
                        raise SourceError("OSV pagination returned an unexpected shape")
                    ids += _parse_vulns(page_results[0])
                    token = page_results[0].get("next_page_token")
                    pages += 1
                if token:
                    raise SourceError("too many result pages")
            except SourceError as exc:
                outcome.errors[comp.key] = str(exc)
                continue
            unique = sorted(set(ids))
            outcome.ids[comp.key] = unique
            self._cache.set("osv-query", comp.key, unique)

    async def fetch(self, ids: dict[str, str]) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
        """Return (records by id, errors by id) for {id: modified}."""
        records: dict[str, dict[str, Any]] = {}
        errors: dict[str, str] = {}
        sem = asyncio.Semaphore(DETAIL_CONCURRENCY)

        async def one(vid: str, modified: str) -> None:
            key = f"{vid}@{modified}"
            cached = self._cache.get("osv-vuln", key)
            if isinstance(cached, dict):
                records[vid] = cached
                return
            if self._offline or self._http is None:
                errors[vid] = "not available in offline cache"
                return
            async with sem:
                try:
                    record = await self._http.get_json(VULN_URL.format(vid))
                except SourceError as exc:
                    errors[vid] = str(exc)
                    return
            if not isinstance(record, dict) or record.get("id") != vid:
                errors[vid] = "unexpected advisory payload"
                return
            records[vid] = record
            self._cache.set("osv-vuln", key, record)

        await asyncio.gather(*(one(v, m) for v, m in sorted(ids.items())))
        return records, errors


def _parse_vulns(result: object) -> list[tuple[str, str]]:
    if not isinstance(result, dict):
        raise SourceError("OSV result is not an object")
    vulns = result.get("vulns", [])
    if not isinstance(vulns, list):
        raise SourceError("OSV vulns is not a list")
    out: list[tuple[str, str]] = []
    for v in vulns:
        vid = v.get("id") if isinstance(v, dict) else None
        if not isinstance(vid, str) or not _ID.match(vid):
            raise SourceError("OSV returned an invalid advisory id")
        out.append((vid, str(v.get("modified", ""))))
    return out
