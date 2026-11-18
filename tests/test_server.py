"""Local web app (`depguard serve`): security controls and API behaviour.

Every test runs against the real FastAPI application (no mocked routing).
Scans run the real engine in offline mode so no network is needed.
"""

from __future__ import annotations

import json
import os
import shutil
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from dep_guard import server as server_module
from dep_guard.engine import ScanOptions, ScanReport, scan
from dep_guard.server.app import SECURITY_HEADERS, Settings, create_app
from dep_guard.server.history import History
from dep_guard.server.security import PathGuard, PathRejected
from tests.osv_mock import FIXTURES

PORT = 8765
TOKEN = "t" * 43
AUTH = {"Authorization": f"Bearer {TOKEN}"}


def offline_scan(target: Path, options: ScanOptions) -> ScanReport:
    options.offline, options.latest, options.nvd = True, False, False
    return scan(target, options)


@pytest.fixture
def root(tmp_path: Path) -> Path:
    base = tmp_path / "allowed"
    shutil.copytree(FIXTURES / "ecosystems" / "cargo", base / "rust-app")
    shutil.copytree(FIXTURES / "projects" / "npm-app", base / "node-app")
    (base / "outside-ish").mkdir()
    (tmp_path / "secret").mkdir()
    (tmp_path / "secret" / "requirements.txt").write_text("private-lib==1.0\n")
    return base


@pytest.fixture
def settings(root: Path, tmp_path: Path) -> Settings:
    return Settings(
        token=TOKEN,
        port=PORT,
        guard=PathGuard.from_strings([str(root)]),
        history=History(tmp_path / "history"),
        cache_dir=tmp_path / "cache",
        scan_fn=offline_scan,
    )


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    # Context-managed: one event loop for the whole test, as under uvicorn.
    with TestClient(
        create_app(settings), base_url=f"http://127.0.0.1:{PORT}", raise_server_exceptions=False
    ) as test_client:
        yield test_client


def scan_body(path: Path, **extra: Any) -> dict[str, Any]:
    return {"path": str(path), "latest": False, "epss": False, "kev": False, **extra}


# ------------------------------------------------------------ access control


def test_api_requires_the_session_token(client: TestClient) -> None:
    assert client.get("/api/info").status_code == 401
    assert client.get("/api/info", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/api/info", headers={"Authorization": TOKEN}).status_code == 401
    response = client.get("/api/info", headers=AUTH)
    assert response.status_code == 200
    assert TOKEN not in response.text  # the token is never echoed


@pytest.mark.parametrize(
    "host",
    ["evil.example", f"evil.example:{PORT}", f"127.0.0.1:{PORT + 1}", "0.0.0.0", ""],  # noqa: S104
)
def test_dns_rebinding_wrong_host_is_refused(client: TestClient, host: str) -> None:
    response = client.get("/api/info", headers={**AUTH, "Host": host})
    assert response.status_code == 400


def test_localhost_alias_is_accepted(client: TestClient) -> None:
    assert client.get("/api/info", headers={**AUTH, "Host": f"localhost:{PORT}"}).status_code == 200


@pytest.mark.parametrize(
    "origin", ["https://evil.example", "http://127.0.0.1:9999", "null", f"https://127.0.0.1:{PORT}"]
)
def test_foreign_origins_are_refused_even_with_the_token(client: TestClient, origin: str) -> None:
    response = client.get("/api/info", headers={**AUTH, "Origin": origin})
    assert response.status_code == 403


def test_same_origin_is_accepted(client: TestClient) -> None:
    headers = {**AUTH, "Origin": f"http://127.0.0.1:{PORT}", "Sec-Fetch-Site": "same-origin"}
    assert client.get("/api/info", headers=headers).status_code == 200


def test_cross_site_fetch_metadata_is_refused(client: TestClient) -> None:
    headers = {**AUTH, "Sec-Fetch-Site": "cross-site"}
    assert client.get("/api/info", headers=headers).status_code == 403


def test_no_cors_preflight_is_ever_approved(client: TestClient) -> None:
    response = client.options(
        "/api/scans",
        headers={
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "authorization,content-type",
        },
    )
    assert response.status_code in (403, 405)
    assert "access-control-allow-origin" not in response.headers


def test_security_headers_and_no_store(client: TestClient) -> None:
    for path, headers in (("/", {}), ("/api/info", AUTH)):
        response = client.get(path, headers=headers)
        for name, value in SECURITY_HEADERS.items():
            assert response.headers[name] == value
    assert client.get("/api/info", headers=AUTH).headers["cache-control"] == "no-store"


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_api_documentation_endpoints_are_disabled(client: TestClient, path: str) -> None:
    assert client.get(path).status_code == 404


# ------------------------------------------------------------- file access


def test_browse_lists_folders_and_dependency_files_only(client: TestClient, root: Path) -> None:
    top = client.get("/api/browse", headers=AUTH).json()
    assert top["dirs"] == [str(root.resolve())]
    listing = client.get("/api/browse", params={"path": str(root / "rust-app")}, headers=AUTH)
    assert listing.status_code == 200
    body = listing.json()
    assert body["files"] == ["Cargo.lock", "Cargo.toml"]
    assert body["parent"] == str(root.resolve())


@pytest.mark.parametrize(
    "make_path",
    [
        lambda root, tmp: str(tmp / "secret"),  # outside the root
        lambda root, tmp: str(root / ".." / "secret"),  # traversal
        lambda root, tmp: "secret",  # relative
        lambda root, tmp: "\\\\evil.example\\share\\x",  # UNC: would leak NTLM on Windows
        lambda root, tmp: "//evil.example/share/x",
        lambda root, tmp: str(root) + chr(0),  # NUL byte
        lambda root, tmp: str(root / ("a" * 5000)),  # absurdly long
        lambda root, tmp: str(root / "does-not-exist"),
    ],
)
def test_paths_outside_the_allowed_roots_are_refused(
    client: TestClient, root: Path, tmp_path: Path, make_path: Any
) -> None:
    path = make_path(root, tmp_path)
    assert client.get("/api/browse", params={"path": path}, headers=AUTH).status_code == 403
    response = client.post("/api/scans", json=scan_body(Path(path)), headers=AUTH)
    assert response.status_code in (403, 422)
    assert "private-lib" not in response.text


def test_unc_paths_are_refused_before_touching_the_file_system(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard = PathGuard.from_strings([str(root)])

    def no_resolve(self: Path, strict: bool = False) -> Path:
        raise AssertionError("resolve() must not run for a UNC path")

    monkeypatch.setattr(Path, "resolve", no_resolve)
    with pytest.raises(PathRejected, match="network and device paths"):
        guard.check("\\\\attacker.example\\share")


@pytest.mark.skipif(os.name == "nt", reason="symlink creation needs privileges on Windows")
def test_symlink_escape_is_refused(client: TestClient, root: Path, tmp_path: Path) -> None:
    (root / "link-out").symlink_to(tmp_path / "secret", target_is_directory=True)
    response = client.get("/api/browse", params={"path": str(root / "link-out")}, headers=AUTH)
    assert response.status_code == 403
    assert "outside" in response.json()["error"]
    listing = client.get("/api/browse", params={"path": str(root)}, headers=AUTH).json()
    assert "link-out" not in listing["dirs"]


# -------------------------------------------------------------------- scans


def test_scan_history_and_exports(client: TestClient, root: Path) -> None:
    response = client.post("/api/scans", json=scan_body(root / "node-app"), headers=AUTH)
    assert response.status_code == 200, response.text
    created = response.json()
    report = created["report"]
    assert report["schema"] == "depguard.report/v1"
    assert report["summary"]["components"] > 0
    assert str(root) not in json.dumps(report)  # reports carry relative paths only

    history = client.get("/api/scans", headers=AUTH).json()["scans"]
    assert [h["id"] for h in history] == [created["id"]]
    again = client.get(f"/api/scans/{created['id']}", headers=AUTH).json()
    assert again["report"] == report

    for fmt, marker in (
        ("json", '"schema": "depguard.report/v1"'),
        ("sarif", '"version": "2.1.0"'),
        ("cyclonedx", '"bomFormat": "CycloneDX"'),
        ("spdx", '"spdxVersion": "SPDX-2.3"'),
    ):
        exported = client.get(f"/api/scans/{created['id']}/export/{fmt}", headers=AUTH)
        assert exported.status_code == 200 and marker in exported.text
        assert exported.headers["content-disposition"].startswith("attachment;")
    assert client.get(f"/api/scans/{created['id']}/export/html", headers=AUTH).status_code == 404

    assert client.delete(f"/api/scans/{created['id']}", headers=AUTH).json() == {"deleted": True}
    assert client.get(f"/api/scans/{created['id']}", headers=AUTH).status_code == 404


@pytest.mark.parametrize(
    "scan_id", ["../../etc/passwd", "..%2f..%2fx", "ABCDEF0123456789", "1" * 17]
)
def test_history_ids_cannot_address_other_files(client: TestClient, scan_id: str) -> None:
    assert client.get(f"/api/scans/{scan_id}", headers=AUTH).status_code == 404
    assert client.delete(f"/api/scans/{scan_id}", headers=AUTH).status_code == 404


@pytest.mark.parametrize(
    "body",
    [
        b"{not json",
        json.dumps({"path": "x", "unexpected": True}).encode(),  # extra fields forbidden
        json.dumps({"path": "x", "fail_on": "P9"}).encode(),
        json.dumps({"path": "x", "latest": "yes please"}).encode(),
        json.dumps({"path": "x", "latest": 1}).encode(),  # strict: no 1 -> True coercion
        json.dumps({"path": 123}).encode(),
        json.dumps({"path": ""}).encode(),
        json.dumps(["path"]).encode(),
    ],
)
def test_request_bodies_are_strictly_validated(client: TestClient, body: bytes) -> None:
    response = client.post(
        "/api/scans", content=body, headers={**AUTH, "Content-Type": "application/json"}
    )
    assert response.status_code == 422


def test_oversized_bodies_are_refused(client: TestClient, root: Path) -> None:
    body = json.dumps(scan_body(root, padding="x" * 20_000)).encode()
    response = client.post(
        "/api/scans", content=body, headers={**AUTH, "Content-Type": "application/json"}
    )
    assert response.status_code == 413


def test_one_scan_at_a_time(client: TestClient, settings: Settings, root: Path) -> None:
    settings.busy = True
    response = client.post("/api/scans", json=scan_body(root / "rust-app"), headers=AUTH)
    assert response.status_code == 409


def test_slow_scans_time_out_and_keep_the_lock_until_they_end(
    client: TestClient, settings: Settings, root: Path
) -> None:
    release = threading.Event()

    def slow(target: Path, options: ScanOptions) -> ScanReport:
        release.wait(5)
        return offline_scan(target, options)

    settings.scan_fn, settings.scan_timeout = slow, 0.2
    response = client.post("/api/scans", json=scan_body(root / "rust-app"), headers=AUTH)
    assert response.status_code == 504
    assert settings.busy  # the worker thread is still running
    release.set()
    deadline = time.monotonic() + 5
    while settings.busy and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not settings.busy


def test_internal_errors_do_not_leak_details(
    client: TestClient, settings: Settings, root: Path
) -> None:
    def broken(target: Path, options: ScanOptions) -> ScanReport:
        raise RuntimeError("secret internal detail C:/Users/someone")

    settings.scan_fn = broken
    response = client.post("/api/scans", json=scan_body(root / "rust-app"), headers=AUTH)
    assert response.status_code == 500
    assert "secret" not in response.text and "someone" not in response.text
    assert not settings.busy


def test_scanned_projects_are_never_executed(client: TestClient, root: Path) -> None:
    project = root / "booby-trapped"
    project.mkdir()
    marker = root / "PWNED"
    (project / "package.json").write_text(
        json.dumps(
            {
                "name": "trap",
                "scripts": {
                    "preinstall": f"node -e \"require('fs').writeFileSync('{marker}', 'x')\""
                },
                "dependencies": {"left-pad": "1.3.0"},
            }
        )
    )
    (project / "setup.py").write_text(f"open({str(marker)!r}, 'w').write('x')\n")
    (project / "conftest.py").write_text(f"open({str(marker)!r}, 'w').write('x')\n")
    before = sorted(p.name for p in project.iterdir())
    response = client.post("/api/scans", json=scan_body(project), headers=AUTH)
    assert response.status_code == 200
    assert not marker.exists()
    assert sorted(p.name for p in project.iterdir()) == before  # read-only: nothing written


# ------------------------------------------------------------------- serve


def test_serve_binds_to_loopback_only(monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
    seen: dict[str, Any] = {}

    def fake_run(self: Any, sockets: list[Any]) -> None:
        seen["address"] = sockets[0].getsockname()
        sockets[0].close()

    import uvicorn  # noqa: PLC0415

    monkeypatch.setattr(uvicorn.Server, "run", fake_run)
    monkeypatch.setattr(server_module.webbrowser, "open", lambda url: seen.setdefault("url", url))
    lines: list[str] = []
    server_module.serve([str(root)], port=0, open_browser=False, announce=lines.append)
    assert seen["address"][0] == "127.0.0.1"
    assert "url" not in seen
    assert lines[0].startswith(f"DepGuard local: http://127.0.0.1:{seen['address'][1]}/#token=")


def test_serve_rejects_a_missing_root(tmp_path: Path) -> None:
    with pytest.raises(server_module.ServeError, match="invalid --root"):
        server_module.serve([str(tmp_path / "nope")], port=0, open_browser=False)


# ------------------------------------------------- session limits and logging


def _client_with_clock(settings: Settings, now: list[float]) -> TestClient:
    settings.clock = lambda: now[0]
    return TestClient(
        create_app(settings), base_url=f"http://127.0.0.1:{PORT}", raise_server_exceptions=False
    )


def test_session_expires_after_inactivity(settings: Settings) -> None:
    now = [1000.0]
    with _client_with_clock(settings, now) as client:
        assert client.get("/api/info", headers=AUTH).status_code == 200
        now[0] += settings.idle_timeout - 1
        assert client.get("/api/info", headers=AUTH).status_code == 200  # activity renews
        now[0] += settings.idle_timeout + 1
        response = client.get("/api/info", headers=AUTH)
        assert response.status_code == 401 and "inactivity" in response.json()["error"]


def test_session_has_an_absolute_lifetime(settings: Settings) -> None:
    now = [0.0]
    with _client_with_clock(settings, now) as client:
        while now[0] < settings.max_lifetime:
            now[0] += settings.idle_timeout / 2  # stay active the whole time
            client.get("/api/info", headers=AUTH)
        now[0] += 1
        response = client.get("/api/info", headers=AUTH)
        assert response.status_code == 401 and "expired" in response.json()["error"]


def test_ending_the_session_revokes_the_token(client: TestClient) -> None:
    assert client.post("/api/session/end", headers=AUTH, json={}).json() == {"ended": True}
    response = client.get("/api/info", headers=AUTH)
    assert response.status_code == 401 and "ended" in response.json()["error"]


def test_security_events_are_logged_without_secrets(
    client: TestClient, root: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level("WARNING", logger="depguard.server.security")
    client.get("/api/info", headers={"Authorization": "Bearer wrong-" + TOKEN})
    client.get("/api/info", headers={**AUTH, "Host": "evil.example"})
    unc = chr(92) * 2 + "evil" + chr(92) + "share"
    client.get("/api/browse", params={"path": unc}, headers=AUTH)
    # Percent-encoded ESC and LF: decoded by the server into request.url.path.
    client.get("/api/x%1B%5B31m%0Aforged-line", headers={"Authorization": "Bearer bad"})
    text = caplog.text
    assert "status=401" in text and "status=400" in text and "status=403" in text
    assert TOKEN not in text  # neither the real token nor the attempted one
    assert chr(0x1B) not in text and "\nforged-line" not in text  # no log injection
    assert all(r.name == "depguard.server.security" for r in caplog.records)


def test_json_declares_its_charset_and_errors_have_one_shape(client: TestClient) -> None:
    assert client.get("/api/info", headers=AUTH).headers["content-type"] == (
        "application/json; charset=utf-8"
    )
    missing = client.get("/api/does-not-exist", headers=AUTH)
    assert missing.status_code == 404 and missing.json() == {"error": "Not Found"}


@pytest.mark.parametrize("method", ["TRACE", "PUT", "PATCH", "CONNECT"])
def test_unused_http_methods_are_refused(client: TestClient, method: str) -> None:
    assert client.request(method, "/api/info", headers=AUTH).status_code == 405
