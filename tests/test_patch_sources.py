"""Patch verification, latest-release lookups (registries) and the NVD fallback."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from dep_guard.engine import ScanOptions, scan
from dep_guard.models import (
    Component,
    ComponentStatus,
    Finding,
    PatchStatus,
    Severity,
)
from dep_guard.patch import classify, is_breaking_upgrade
from dep_guard.sources import nvd as nvd_module
from dep_guard.sources.cache import Cache
from dep_guard.sources.http import HttpClient, SourceError, new_client
from dep_guard.sources.registries import (
    NOT_FOUND,
    RegistrySource,
    _crates_index_path,
    _go_escape,
    _maven_stable,
)
from tests.conftest import PROJECTS, TODAY
from tests.osv_mock import MockState, install, load_state

# ------------------------------------------------------------------ helpers


def comp(
    version: str | None = "1.0.0",
    status: ComponentStatus = ComponentStatus.CLEAN,
    latest: str | None = None,
    ecosystem: str = "npm",
    name: str = "pkg",
) -> Component:
    c = Component(ecosystem, name, version, f"pkg:{ecosystem.lower()}/{name}", status=status)
    c.latest = latest
    return c


def finding(c: Component, fixed: list[str]) -> Finding:
    return Finding(
        component=c,
        id="GHSA-x",
        aliases=["GHSA-x"],
        summary="s",
        severity=Severity.HIGH,
        cvss_score=None,
        cvss_vector=None,
        cwes=[],
        fixed_versions=fixed,
        references=[],
        published=None,
    )


# ------------------------------------------------------------- patch states


@pytest.mark.parametrize(
    ("current", "target", "breaking"),
    [
        ("1.2.3", "1.9.0", False),
        ("1.2.3", "2.0.0", True),
        ("0.18.5", "0.20.0", True),  # SemVer: a 0.x minor bump is breaking
        ("0.18.5", "0.18.9", False),
        ("v1.6.0", "v2.0.0", True),  # Go
        ("29.0-jre", "33.0.0-jre", True),  # Maven qualifiers after the number
        ("abc", "1.0.0", None),
        (None, "1.0.0", None),
    ],
)
def test_breaking_upgrade_detection(
    current: str | None, target: str, breaking: bool | None
) -> None:
    assert is_breaking_upgrade(current, target) is breaking


def test_every_patch_state_with_its_reason() -> None:
    unresolved = comp(None, ComponentStatus.UNRESOLVED)
    unresolved.unresolved_reason = "version range (^1.0.0)"
    assert classify(unresolved, []) == (
        PatchStatus.UNIDENTIFIABLE_VERSION,
        "version range (^1.0.0)",
    )

    errored = comp(status=ComponentStatus.ERROR)
    errored.error = "timeout"
    assert classify(errored, [])[0] is PatchStatus.INSUFFICIENT_DATA
    assert classify(comp(status=ComponentStatus.PRIVATE), [])[0] is PatchStatus.INSUFFICIENT_DATA

    assert classify(comp(), []) == (
        PatchStatus.NO_KNOWN_VULNERABILITIES,
        "última versión no consultada",
    )
    assert classify(comp(latest="1.0.0"), [])[0] is PatchStatus.UP_TO_DATE
    assert classify(comp("1.1.0", latest="1.0.0"), [])[0] is PatchStatus.UP_TO_DATE
    state, note = classify(comp(latest="2.1.0"), [])
    assert (state, note) == (PatchStatus.OUTDATED, "2.1.0 disponible (cambio de versión mayor)")

    vulnerable = comp(status=ComponentStatus.VULNERABLE, latest="1.4.0")
    state, note = classify(
        vulnerable, [finding(vulnerable, ["1.0.2"]), finding(vulnerable, ["1.1.0"])]
    )
    assert state is PatchStatus.VULNERABLE_FIX_AVAILABLE
    assert note == "actualizar a 1.1.0 (corrige 2 de 2); la última versión es 1.4.0"

    state, note = classify(vulnerable, [finding(vulnerable, ["1.1.0"]), finding(vulnerable, [])])
    assert state is PatchStatus.VULNERABLE_NO_FIX
    assert note.startswith("1 de 2 avisos sin versión corregida; 1.1.0 corrige 1")


def test_latest_published_is_not_latest_safe() -> None:
    c = comp(status=ComponentStatus.VULNERABLE, latest="3.0.0")
    c.latest_vulnerable = True
    _, note = classify(c, [finding(c, ["1.0.1"])])
    assert "la última versión 3.0.0 también está afectada" in note

    outdated = comp(latest="1.5.0")
    outdated.latest_vulnerable = True
    assert classify(outdated, [])[1] == "1.5.0 disponible; 1.5.0 tiene avisos conocidos"

    on_latest = comp(status=ComponentStatus.VULNERABLE, latest="1.0.0")
    assert classify(on_latest, [finding(on_latest, [])])[1].endswith(
        "ya es la última versión publicada"
    )


# --------------------------------------------------------------- registries


def test_registry_path_encodings() -> None:
    assert _crates_index_path("a") == "1/a"
    assert _crates_index_path("ab") == "2/ab"
    assert _crates_index_path("syn") == "3/s/syn"
    assert _crates_index_path("SmallVec") == "sm/al/smallvec"
    assert _go_escape("github.com/BurntSushi/toml") == "github.com/!burnt!sushi/toml"


@pytest.mark.parametrize(
    ("version", "stable"),
    [
        ("33.0.0-jre", True),
        ("5.6.Final", True),
        ("1.0.RELEASE", True),
        ("2.0.0-RC1", False),
        ("3.0.0-M1", False),
        ("1.0-SNAPSHOT", False),
        ("6.0.0.Beta1", False),
    ],
)
def test_maven_prerelease_qualifiers(version: str, stable: bool) -> None:
    assert _maven_stable(version) is stable


CRATES_INDEX = "\n".join(
    json.dumps(row)
    for row in [
        {"name": "smallvec", "vers": "1.6.0", "yanked": False},
        {"name": "smallvec", "vers": "1.13.2", "yanked": False},
        {"name": "smallvec", "vers": "1.14.0", "yanked": True},
        {"name": "smallvec", "vers": "2.0.0-alpha.1", "yanked": False},
    ]
)
MAVEN_METADATA = """<?xml version="1.0" encoding="UTF-8"?>
<metadata><groupId>g</groupId><artifactId>a</artifactId><versioning>
<latest>3.0.0-M1</latest><release>3.0.0-M1</release>
<versions><version>2.9.0</version><version>2.17.0</version><version>3.0.0-M1</version></versions>
</versioning></metadata>"""


@pytest.fixture
def registries() -> Iterator[respx.MockRouter]:
    with respx.mock(assert_all_called=False) as router:
        router.get("https://pypi.org/pypi/requests/json").respond(
            json={"info": {"version": "2.32.3"}}
        )
        router.get("https://pypi.org/pypi/ghost-internal-pkg/json").respond(404)
        router.get("https://registry.npmjs.org/@babel/core/latest").respond(
            json={"version": "7.26.0"}
        )
        router.get("https://index.crates.io/sm/al/smallvec").respond(text=CRATES_INDEX)
        router.get("https://proxy.golang.org/github.com/!burnt!sushi/toml/@latest").respond(
            json={"Version": "v1.4.0"}
        )
        router.get("https://repo.packagist.org/p2/symfony/http-kernel.json").respond(
            json={
                "packages": {
                    "symfony/http-kernel": [
                        {"version": "v8.0.0-BETA2", "version_normalized": "8.0.0.0-beta2"},
                        {"version": "v7.3.1", "version_normalized": "7.3.1.0"},
                    ]
                }
            }
        )
        router.get("https://repo1.maven.org/maven2/g/a/maven-metadata.xml").respond(
            text=MAVEN_METADATA
        )
        router.get("https://api.nuget.org/v3-flatcontainer/serilog/index.json").respond(
            json={"versions": ["2.10.0", "4.2.0", "5.0.0-dev-1"]}
        )
        router.get("https://registry.npmjs.org/flaky/latest").respond(503)
        yield router


def _latest(components: list[Component], tmp_path: Path, online: bool = True) -> Any:
    async def run() -> Any:
        async with new_client(5) as client:
            http = HttpClient(client, retries=0) if online else None
            return await RegistrySource(http, Cache(tmp_path)).latest(components)

    return asyncio.run(run())


def test_latest_stable_release_per_registry(registries: respx.MockRouter, tmp_path: Path) -> None:
    components = [
        comp("2.19.0", ecosystem="PyPI", name="requests"),
        comp("7.0.0", ecosystem="npm", name="@babel/core"),
        comp("1.6.0", ecosystem="crates.io", name="smallvec"),
        comp("v1.2.0", ecosystem="Go", name="github.com/BurntSushi/toml"),
        comp("v4.4.0", ecosystem="Packagist", name="symfony/http-kernel"),
        comp("2.9.0", ecosystem="Maven", name="g:a"),
        comp("2.10.0", ecosystem="NuGet", name="Serilog"),
    ]
    outcome = _latest(components, tmp_path)
    assert {c.name: outcome.latest.get(c.key) for c in components} == {
        "requests": "2.32.3",
        "@babel/core": "7.26.0",
        "smallvec": "1.13.2",  # yanked and pre-releases skipped
        "github.com/BurntSushi/toml": "v1.4.0",
        "symfony/http-kernel": "v7.3.1",  # BETA skipped
        "g:a": "2.17.0",  # milestone release skipped
        "Serilog": "4.2.0",  # -dev skipped
    }
    assert outcome.errors == 0


def test_not_found_and_failures_are_reported_never_guessed(
    registries: respx.MockRouter, tmp_path: Path
) -> None:
    ghost = comp("1.0.0", ecosystem="PyPI", name="ghost-internal-pkg")
    flaky = comp("1.0.0", ecosystem="npm", name="flaky")
    hex_pkg = comp("1.0.0", ecosystem="Hex", name="plug")
    outcome = _latest([ghost, flaky, hex_pkg], tmp_path)
    assert outcome.latest == {}
    assert outcome.notes[ghost.key] == NOT_FOUND
    assert outcome.notes[flaky.key].startswith("falló la consulta al registro")
    assert outcome.notes[hex_pkg.key] == "sin consulta de registro para Hex"
    assert outcome.errors == 1


def test_latest_lookups_are_cached_and_work_offline(
    registries: respx.MockRouter, tmp_path: Path
) -> None:
    requests_comp = comp("2.19.0", ecosystem="PyPI", name="requests")
    _latest([requests_comp], tmp_path)
    calls = registries.calls.call_count
    offline = _latest([requests_comp], tmp_path, online=False)
    assert offline.latest[requests_comp.key] == "2.32.3"
    assert registries.calls.call_count == calls
    uncached = comp("1.0.0", ecosystem="PyPI", name="other")
    assert (
        _latest([uncached], tmp_path, online=False).notes[uncached.key]
        == "no disponible sin conexión"
    )


def test_registry_hosts_are_allowlisted_and_redirects_refused(tmp_path: Path) -> None:
    async def run(url: str) -> Any:
        async with new_client(5) as client:
            return await HttpClient(client, retries=0).get_json(url)

    with pytest.raises(SourceError, match="non-allowlisted"):
        asyncio.run(run("https://evil.example/pypi/requests/json"))
    with pytest.raises(SourceError, match="non-allowlisted"):
        asyncio.run(run("http://pypi.org/pypi/requests/json"))  # plain HTTP
    with respx.mock() as router:
        router.get("https://pypi.org/pypi/x/json").respond(
            302, headers={"Location": "https://evil.example/"}
        )
        with pytest.raises(SourceError, match="HTTP 302"):
            asyncio.run(run("https://pypi.org/pypi/x/json"))


# ---------------------------------------------------------- engine (latest)


@pytest.fixture
def osv_and_registries() -> Iterator[tuple[MockState, respx.MockRouter]]:
    state = load_state()
    # acme-qs 6.2.4 is the latest release; give it an advisory too.
    state.index["npm|acme-qs|6.9.0"] = ["GHSA-dmo1-qs62-0001"]
    latest = {"acme-qs": "6.9.0", "acme-router": "4.1.2", "acme-test": "3.0.0"}
    with respx.mock(assert_all_called=False) as router:
        install(router, state)
        router.get(url__regex=r"^https://registry\.npmjs\.org/.+/latest$").mock(
            side_effect=lambda request: (
                httpx.Response(200, json={"version": latest[name]})
                if (name := request.url.path.split("/")[1]) in latest
                else httpx.Response(404)
            )
        )
        yield state, router


def test_scan_with_latest_distinguishes_every_state(
    osv_and_registries: tuple[MockState, respx.MockRouter], tmp_path: Path
) -> None:
    report = scan(
        PROJECTS / "npm-app",
        ScanOptions(today=TODAY, cache_dir=tmp_path, latest=True),
    )
    by = {(c.name, c.version): c for c in report.components}
    qs = by[("acme-qs", "6.2.0")]
    assert qs.latest == "6.9.0" and qs.latest_vulnerable is True
    assert qs.patch_status is PatchStatus.VULNERABLE_FIX_AVAILABLE
    assert "la última versión 6.9.0 también está afectada" in qs.patch_note
    assert by[("acme-router", "4.1.2")].patch_status is PatchStatus.UP_TO_DATE
    test_pkg = by[("acme-test", "2.3.0")]
    assert (test_pkg.patch_status, test_pkg.latest_vulnerable) == (PatchStatus.OUTDATED, False)
    assert report.sources["registries"] == "ok"
    # A package missing from the public registry says so (dependency-confusion signal).
    cookie = by[("acme-cookie", "0.5.0")]
    assert cookie.latest is None and cookie.latest_note == "no existe en el registro público"


# --------------------------------------------------------------------- NVD

NVD_V31 = {
    "id": "CVE-2099-1000",
    "metrics": {
        "cvssMetricV31": [
            {
                "type": "Secondary",
                "cvssData": {"vectorString": "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"},
            },
            {
                "type": "Primary",
                "cvssData": {"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
            },
        ]
    },
    "weaknesses": [
        {"description": [{"value": "CWE-502"}, {"value": "NVD-CWE-noinfo"}]},
        {"description": [{"value": "CWE-20"}]},
    ],
}
NVD_V40 = {
    "id": "CVE-2099-2000",
    "metrics": {"cvssMetricV40": [{"type": "Primary", "cvssData": {"baseScore": 6.9}}]},
}


def test_nvd_parsing_prefers_primary_v31_and_scores_it_locally() -> None:
    m = nvd_module.parse_cve(NVD_V31)
    assert (m.score, m.severity, m.source) == (9.8, Severity.CRITICAL, "nvd_cvss_v3")
    assert m.cwes == ("CWE-20", "CWE-502")  # NVD-CWE-* placeholders dropped
    v4 = nvd_module.parse_cve(NVD_V40)
    assert (v4.score, v4.severity, v4.source) == (6.9, Severity.MEDIUM, "nvd_cvss_v4")
    empty = nvd_module.parse_cve({"id": "CVE-2099-3000"})
    assert (empty.score, empty.severity) == (None, Severity.UNKNOWN)


def test_nvd_fills_only_findings_without_a_cvss_score() -> None:
    c = comp()
    unscored = finding(c, [])
    unscored.aliases = ["CVE-2099-1000", "GHSA-x"]
    unscored.severity = Severity.UNKNOWN
    scored = finding(c, [])
    scored.aliases = ["CVE-2099-1000"]
    scored.cvss_score, scored.severity = 5.0, Severity.MEDIUM
    metrics = {"CVE-2099-1000": nvd_module.parse_cve(NVD_V31)}
    assert nvd_module.apply([unscored, scored], metrics) == 1
    assert (unscored.cvss_score, unscored.severity, unscored.severity_source) == (
        9.8,
        Severity.CRITICAL,
        "nvd_cvss_v3",
    )
    assert scored.cvss_score == 5.0  # OSV data is never overridden


def test_nvd_requests_are_paced_capped_and_key_is_sent_only_as_header(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(nvd_module, "MAX_LOOKUPS", 3)
    slept: list[float] = []
    now = [0.0]

    async def fake_sleep(seconds: float) -> None:
        slept.append(seconds)
        now[0] += seconds

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("apiKey") in (None, "secret-key")
        assert "secret-key" not in str(request.url)
        cve = request.url.params["cveId"]
        return httpx.Response(200, json={"vulnerabilities": [{"cve": {**NVD_V31, "id": cve}}]})

    async def run(key: str | None) -> Any:
        async with new_client(5) as client:
            source = nvd_module.NvdSource(
                HttpClient(client, retries=0),
                Cache(tmp_path / (key or "nokey")),
                api_key=key,
                sleep=fake_sleep,
                clock=lambda: now[0],
            )
            return await source.lookup([f"CVE-2099-100{i}" for i in range(5)])

    with respx.mock() as router:
        router.get(nvd_module.NVD_URL).mock(side_effect=handler)
        found, warning = asyncio.run(run(None))
        assert len(found) == 3 and warning and "only 3 of 5" in warning
        assert slept == [6.5, 6.5]  # 5 requests / 30 s without a key
        slept.clear()
        asyncio.run(run("secret-key"))
        assert slept == [0.7, 0.7]
        headers = [c.request.headers.get("apiKey") for c in router.calls]
        assert headers[-1] == "secret-key"


def test_nvd_outage_keeps_osv_severity(tmp_path: Path) -> None:
    async def run() -> Any:
        async with new_client(5) as client:
            source = nvd_module.NvdSource(HttpClient(client, retries=0), Cache(tmp_path), "k")
            return await source.lookup(["CVE-2099-1000"])

    with respx.mock() as router:
        router.get(nvd_module.NVD_URL).respond(503)
        found, warning = asyncio.run(run())
    assert found == {} and warning and warning.startswith("NVD unavailable")
