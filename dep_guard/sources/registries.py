"""Latest published *stable* version of a package, from each official registry.

Only used to tell "up to date" from "outdated". It never decides whether a
version is vulnerable (that is OSV's job), and the latest published version
is not assumed to be safe: the engine queries OSV for it separately.

| Ecosystem | Endpoint (documented, public, no auth) |
|---|---|
| PyPI      | https://pypi.org/pypi/{name}/json -> info.version |
| npm       | https://registry.npmjs.org/{name}/latest -> version (the `latest` dist-tag) |
| crates.io | https://index.crates.io/{prefix}/{name} (sparse index, see below) |
| Go        | https://proxy.golang.org/{escaped module}/@latest -> Version |
| Packagist | https://repo.packagist.org/p2/{vendor}/{name}.json |
| Maven     | https://repo1.maven.org/maven2/{group path}/{artifact}/maven-metadata.xml |
| NuGet     | https://api.nuget.org/v3-flatcontainer/{id}/index.json |

The crates.io web API asks crawlers for 1 request/second; the sparse index
is the CDN that cargo itself uses.

Pre-releases, yanked crates, snapshots and milestones are skipped. A 404 is
a meaningful answer ("not in the public registry", e.g. an internal package
that should be listed in `private_packages`), not an error.
"""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

from dep_guard.adapters.base import ParseError
from dep_guard.adapters.safe_formats import children, first, local_name, parse_xml
from dep_guard.models import Component
from dep_guard.sources.cache import Cache
from dep_guard.sources.http import HttpClient, SourceError
from dep_guard.textutil import clean
from dep_guard.versions import compare_semver, is_semver

DAY = 24 * 3600
CONCURRENCY = 8
NOT_FOUND = "no existe en el registro público"
# Maven qualifiers that mark a pre-release ("33.0.0-jre" or "5.6.Final" are stable).
_MAVEN_PRE = re.compile(
    r"(?i)(?:^|[-.])(alpha|beta|rc|cr|milestone|preview|snapshot|ea|dev|a|b|m)[-.]?\d*(?=$|[-.])"
)
_VERSION_TEXT = re.compile(r"^[0-9A-Za-z.+_~!-]{1,64}$")


@dataclass(slots=True)
class LatestOutcome:
    latest: dict[str, str] = field(default_factory=dict)  # component.key -> version
    notes: dict[str, str] = field(default_factory=dict)  # component.key -> why unknown
    errors: int = 0


def _stable(version: str) -> bool:
    """SemVer-style ecosystems (npm, crates.io, NuGet): a "-" starts a pre-release."""
    return "-" not in version.split("+", 1)[0]


def _maven_stable(version: str) -> bool:
    return not _MAVEN_PRE.search(version)


def _checked(version: object) -> str | None:
    if isinstance(version, str) and _VERSION_TEXT.match(version):
        return version
    return None


def _crates_index_path(name: str) -> str:
    n = name.lower()
    if len(n) <= 2:
        return f"{len(n)}/{n}"
    if len(n) == 3:
        return f"3/{n[0]}/{n}"
    return f"{n[:2]}/{n[2:4]}/{n}"


def _go_escape(module: str) -> str:
    """Module path case-encoding used by the Go module proxy protocol."""
    return "".join(f"!{c.lower()}" if c.isupper() else c for c in module)


def _semver_max(versions: list[str]) -> str | None:
    best: str | None = None
    for v in versions:
        if best is None or (compare_semver(v, best) or 0) > 0:
            best = v
    return best


Fetcher = Callable[[HttpClient, str], Awaitable[str | None]]


async def _pypi(http: HttpClient, name: str) -> str | None:
    data = await http.get_json(
        f"https://pypi.org/pypi/{quote(name, safe='')}/json", none_on_404=True
    )
    if data is None:
        raise LookupError(NOT_FOUND)
    info = data.get("info") if isinstance(data, dict) else None
    return _checked(info.get("version")) if isinstance(info, dict) else None


async def _npm(http: HttpClient, name: str) -> str | None:
    url = f"https://registry.npmjs.org/{quote(name, safe='@')}/latest"
    data = await http.get_json(url, none_on_404=True)
    if data is None:
        raise LookupError(NOT_FOUND)
    return _checked(data.get("version")) if isinstance(data, dict) else None


async def _crates(http: HttpClient, name: str) -> str | None:
    text = await http.get_text(
        f"https://index.crates.io/{_crates_index_path(name)}", none_on_404=True
    )
    if text is None:
        raise LookupError(NOT_FOUND)
    versions: list[str] = []
    for line in text.splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        vers = _checked(row.get("vers")) if isinstance(row, dict) else None
        if vers and not row.get("yanked") and is_semver(vers) and _stable(vers):
            versions.append(vers)
    return _semver_max(versions)


async def _go(http: HttpClient, name: str) -> str | None:
    url = f"https://proxy.golang.org/{quote(_go_escape(name), safe='/!')}/@latest"
    data = await http.get_json(url, none_on_404=True)
    if data is None:
        raise LookupError(NOT_FOUND)
    return _checked(data.get("Version")) if isinstance(data, dict) else None


async def _packagist(http: HttpClient, name: str) -> str | None:
    if name.count("/") != 1:
        return None
    url = f"https://repo.packagist.org/p2/{quote(name.lower(), safe='/')}.json"
    data = await http.get_json(url, none_on_404=True)
    if data is None:
        raise LookupError(NOT_FOUND)
    packages = data.get("packages") if isinstance(data, dict) else None
    entries = packages.get(name.lower()) if isinstance(packages, dict) else None
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict):
            continue
        normalized = str(entry.get("version_normalized", ""))
        version = _checked(entry.get("version"))
        if version and "-" not in normalized:
            return version  # p2 lists newest first
    return None


async def _maven(http: HttpClient, name: str) -> str | None:
    group, _, artifact = name.partition(":")
    if not group or not artifact:
        return None
    url = (
        f"https://repo1.maven.org/maven2/{quote(group.replace('.', '/'), safe='/')}/"
        f"{quote(artifact, safe='')}/maven-metadata.xml"
    )
    text = await http.get_text(url, none_on_404=True)
    if text is None:
        raise LookupError(NOT_FOUND)
    try:
        root = parse_xml(text)
    except ParseError as exc:
        raise SourceError(f"Maven metadata: {exc}") from None
    versioning = first(root, "versioning")
    listed = [
        (v.text or "").strip()
        for v in children(first(versioning, "versions"), "version")
        if local_name(v.tag) == "version"
    ]
    stable = [v for v in listed if _checked(v) and _maven_stable(v)]
    release = next(((c.text or "").strip() for c in children(versioning, "release")), None)
    if release and release in stable:
        return release
    return stable[-1] if stable else None  # listed in deployment order


async def _nuget(http: HttpClient, name: str) -> str | None:
    url = f"https://api.nuget.org/v3-flatcontainer/{quote(name.lower(), safe='')}/index.json"
    data = await http.get_json(url, none_on_404=True)
    if data is None:
        raise LookupError(NOT_FOUND)
    versions = data.get("versions") if isinstance(data, dict) else None
    stable = [v for v in versions or [] if _checked(v) and _stable(v)]
    return stable[-1] if stable else None  # the index is sorted ascending


FETCHERS: dict[str, Fetcher] = {
    "PyPI": _pypi,
    "npm": _npm,
    "crates.io": _crates,
    "Go": _go,
    "Packagist": _packagist,
    "Maven": _maven,
    "NuGet": _nuget,
}


class RegistrySource:
    def __init__(self, http: HttpClient | None, cache: Cache, ttl: float = DAY) -> None:
        self._http, self._cache, self._ttl = http, cache, ttl

    async def latest(self, components: list[Component]) -> LatestOutcome:
        outcome = LatestOutcome()
        sem = asyncio.Semaphore(CONCURRENCY)
        pending: dict[tuple[str, str], list[Component]] = {}
        for comp in components:
            if comp.ecosystem not in FETCHERS:
                outcome.notes[comp.key] = f"sin consulta de registro para {comp.ecosystem}"
                continue
            pending.setdefault((comp.ecosystem, comp.name), []).append(comp)

        async def one(eco: str, name: str, comps: list[Component]) -> None:
            cache_key = f"{eco}:{name}"
            cached = self._cache.get("latest", cache_key, self._ttl)
            value: Any
            if isinstance(cached, dict):
                value = cached
            elif self._http is None:
                value = {"note": "no disponible sin conexión"}
            else:
                async with sem:
                    try:
                        found = await FETCHERS[eco](self._http, name)
                        value = {"version": found} if found else {"note": "sin versión estable"}
                        self._cache.set("latest", cache_key, value)
                    except LookupError as exc:
                        value = {"note": str(exc)}
                        self._cache.set("latest", cache_key, value)
                    except (SourceError, ValueError, AttributeError) as exc:
                        outcome.errors += 1
                        value = {"note": f"falló la consulta al registro: {clean(str(exc), 120)}"}
            for comp in comps:
                if isinstance(value.get("version"), str):
                    outcome.latest[comp.key] = value["version"]
                else:
                    outcome.notes[comp.key] = str(value.get("note", "unknown"))

        await asyncio.gather(*(one(e, n, c) for (e, n), c in sorted(pending.items())))
        return outcome
