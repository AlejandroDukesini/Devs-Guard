"""Fake OSV / EPSS / KEV HTTP endpoints backed by fixtures/osv-mock.

Used by the test-suite and by tests/regen_golden.py. Failure injection
(`fail`) lets tests prove that outages produce INCOMPLETE, never PASS.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote

import httpx
import respx

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"
MOCK = FIXTURES / "osv-mock"


@dataclass
class MockState:
    index: dict[str, list[str]]
    modified: str
    epss: dict[str, list[float]]
    kev: dict[str, object]
    fail: dict[str, object] = field(
        default_factory=dict
    )  # endpoint -> status code or "timeout"/"garbage"
    calls: dict[str, int] = field(
        default_factory=lambda: {"batch": 0, "vuln": 0, "epss": 0, "kev": 0}
    )

    def _failure(self, endpoint: str) -> httpx.Response | None:
        how = self.fail.get(endpoint)
        if how is None:
            return None
        if how == "timeout":
            raise httpx.ReadTimeout("mock timeout")
        if how == "garbage":
            return httpx.Response(200, content=b"<html>not json</html>")
        return httpx.Response(int(how))  # type: ignore[call-overload]

    def batch(self, request: httpx.Request) -> httpx.Response:
        self.calls["batch"] += 1
        if (failed := self._failure("batch")) is not None:
            return failed
        body = json.loads(request.content)
        results = []
        for q in body["queries"]:
            key = f"{q['package']['ecosystem']}|{q['package']['name']}|{q['version']}"
            ids = self.index.get(key, [])
            results.append(
                {"vulns": [{"id": i, "modified": self.modified} for i in ids]} if ids else {}
            )
        return httpx.Response(200, json={"results": results})

    def vuln(self, request: httpx.Request) -> httpx.Response:
        self.calls["vuln"] += 1
        if (failed := self._failure("vuln")) is not None:
            return failed
        vid = unquote(request.url.path.rsplit("/", 1)[-1])
        path = MOCK / "vulns" / f"{vid}.json"
        if not path.is_file():
            return httpx.Response(404, json={"code": 5, "message": "Bug not found."})
        return httpx.Response(200, content=path.read_bytes())

    def epss_handler(self, request: httpx.Request) -> httpx.Response:
        self.calls["epss"] += 1
        if (failed := self._failure("epss")) is not None:
            return failed
        cves = request.url.params.get("cve", "").split(",")
        data = [
            {
                "cve": c,
                "epss": f"{self.epss[c][0]:.9f}",
                "percentile": f"{self.epss[c][1]:.9f}",
                "date": "2099-01-01",
            }
            for c in cves
            if c in self.epss
        ]
        return httpx.Response(200, json={"status": "OK", "data": data})

    def kev_handler(self, request: httpx.Request) -> httpx.Response:
        self.calls["kev"] += 1
        if (failed := self._failure("kev")) is not None:
            return failed
        return httpx.Response(200, json=self.kev)


def load_state() -> MockState:
    index = json.loads((MOCK / "index.json").read_text(encoding="utf-8"))
    return MockState(
        index=index["results"],
        modified=index["modified"],
        epss=json.loads((MOCK / "epss.json").read_text(encoding="utf-8")),
        kev=json.loads((MOCK / "kev.json").read_text(encoding="utf-8")),
    )


def install(router: respx.MockRouter, state: MockState) -> None:
    # Late binding (lambda) so tests can swap state.batch for a spy/flaky handler.
    router.post("https://api.osv.dev/v1/querybatch").mock(side_effect=lambda r: state.batch(r))  # noqa: PLW0108
    router.get(url__regex=r"https://api\.osv\.dev/v1/vulns/.+").mock(side_effect=state.vuln)
    router.get(url__startswith="https://api.first.org/data/v1/epss").mock(
        side_effect=state.epss_handler
    )
    router.get(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    ).mock(side_effect=state.kev_handler)
