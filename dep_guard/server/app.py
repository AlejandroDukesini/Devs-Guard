"""FastAPI application of the local web app. See security.py for the threat model.

Endpoints (all under /api require the session token):
  GET    /api/info                     version, allowed roots, defaults
  GET    /api/browse?path=             sub-folders and dependency files of a folder
  POST   /api/scans                    run a scan (one at a time, bounded time)
  GET    /api/scans                    history (newest first)
  GET    /api/scans/{id}               one report (depguard.report/v1)
  DELETE /api/scans/{id}               forget one scan
  GET    /api/scans/{id}/export/{fmt}  json | sarif | cyclonedx | spdx download
The scan is read-only: manifests are parsed as text; nothing in the scanned
project is executed, installed or modified.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from dep_guard import __version__
from dep_guard.adapters import NOT_ANALYSED, adapter_for
from dep_guard.discovery import SKIP_DIRS
from dep_guard.engine import ScanOptions, ScanReport, ToolError, scan
from dep_guard.models import Priority
from dep_guard.reporters import cyclonedx, json_report, sarif, spdx
from dep_guard.server.history import History
from dep_guard.server.security import OriginPolicy, PathGuard, PathRejected, token_matches
from dep_guard.textutil import clean

log = logging.getLogger("depguard.server")
# Security events (ASVS V16.3): rejected requests, expired sessions, refused paths.
# Never contains the session token; request data is sanitised (log injection).
security_log = logging.getLogger("depguard.server.security")

STATIC_DIR = Path(__file__).resolve().parent / "static"
MAX_BODY_BYTES = 16 * 1024
MAX_LISTING = 500
SCAN_TIMEOUT_S = 600.0
# Session limits (ASVS V7.3): restart `depguard serve` to get a new session.
IDLE_TIMEOUT_S = 60 * 60.0
MAX_LIFETIME_S = 12 * 60 * 60.0

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; "
    "form-action 'none'; frame-ancestors 'none'"
)
SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), usb=(), payment=()",
}
EXPORTS: dict[str, tuple[str, str]] = {
    "json": ("depguard-report.json", "application/json"),
    "sarif": ("depguard.sarif", "application/sarif+json"),
    "cyclonedx": ("bom.cdx.json", "application/vnd.cyclonedx+json"),
    "spdx": ("sbom.spdx.json", "application/spdx+json"),
}


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = Field(min_length=1, max_length=4096)
    latest: bool = True
    nvd: bool = False
    epss: bool = True
    kev: bool = True
    offline: bool = False
    fail_on: Literal["P0", "P1", "P2", "P3", "none"] | None = None


@dataclass(slots=True)
class Settings:
    token: str
    port: int
    guard: PathGuard
    history: History
    cache_dir: Path | None = None
    scan_timeout: float = SCAN_TIMEOUT_S
    scan_fn: Callable[[Path, ScanOptions], ScanReport] = scan
    busy: bool = field(default=False)
    idle_timeout: float = IDLE_TIMEOUT_S
    max_lifetime: float = MAX_LIFETIME_S
    clock: Callable[[], float] = time.monotonic
    started: float | None = None
    last_seen: float | None = None
    ended: bool = False  # set by POST /api/session/end, never reset


class Utf8JSONResponse(JSONResponse):
    """JSON with an explicit charset (ASVS V4.1.1)."""

    media_type = "application/json; charset=utf-8"


def _error(status: int, message: str) -> JSONResponse:
    return Utf8JSONResponse({"error": message}, status_code=status)


def _deny(request: Request, status: int, reason: str) -> JSONResponse:
    client = request.client.host if request.client else "-"
    security_log.warning(
        "denied status=%d reason=%s method=%s path=%s client=%s",
        status,
        reason,
        clean(request.method, 10),
        clean(request.url.path, 200),
        clean(client, 60),
    )
    return _error(status, reason)


def create_app(settings: Settings) -> FastAPI:
    app = FastAPI(
        title="DepGuard local",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        default_response_class=Utf8JSONResponse,
    )
    origins = OriginPolicy(settings.port)
    settings.started = settings.last_seen = settings.clock()

    @app.middleware("http")
    async def guard(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await _check(request, call_next)
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    async def _check(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if not origins.host_ok(request.headers.get("host")):
            return _deny(request, 400, "invalid Host header")
        if not origins.origin_ok(request.headers.get("origin")):
            return _deny(request, 403, "cross-origin request refused")
        if request.headers.get("sec-fetch-site") not in (None, "same-origin", "none"):
            return _deny(request, 403, "cross-site request refused")
        if request.url.path.startswith("/api/"):
            if not token_matches(settings.token, request.headers.get("authorization")):
                return _deny(request, 401, "missing or invalid session token")
            now = settings.clock()
            started = now if settings.started is None else settings.started
            last_seen = now if settings.last_seen is None else settings.last_seen
            if settings.ended:
                return _deny(request, 401, "session ended; restart depguard serve")
            if now - started > settings.max_lifetime:
                return _deny(request, 401, "session expired; restart depguard serve")
            if now - last_seen > settings.idle_timeout:
                return _deny(
                    request, 401, "session expired after inactivity; restart depguard serve"
                )
            settings.last_seen = now
            if request.method in ("POST", "PUT", "PATCH"):
                length = request.headers.get("content-length")
                if length is None:
                    return _deny(request, 411, "Content-Length required")
                if not length.isdigit() or int(length) > MAX_BODY_BYTES:
                    return _deny(request, 413, "request body too large")
        return await call_next(request)

    @app.exception_handler(PathRejected)
    async def _path_rejected(request: Request, exc: PathRejected) -> JSONResponse:
        return _deny(request, 403, str(exc))

    @app.exception_handler(Exception)
    async def _unexpected(_request: Request, exc: Exception) -> JSONResponse:
        log.error("unexpected error (%s); details at debug level", type(exc).__name__)
        log.debug("unhandled error", exc_info=exc)
        return _error(500, "internal error (details are not exposed; run with -vv)")

    @app.post("/api/session/end")
    async def end_session() -> dict[str, bool]:
        settings.ended = True
        security_log.warning("session ended by the user; the token is no longer accepted")
        return {"ended": True}

    @app.get("/api/info")
    async def info() -> dict[str, Any]:
        return {
            "name": "DepGuard",
            "version": __version__,
            "roots": settings.guard.display_roots(),
            "defaults": ScanRequest(path="x").model_dump(exclude={"path"}),
            "exports": list(EXPORTS),
        }

    @app.get("/api/browse")
    async def browse(path: str | None = None) -> dict[str, Any]:
        if path is None:
            return {
                "path": None,
                "parent": None,
                "dirs": settings.guard.display_roots(),
                "files": [],
            }
        folder = settings.guard.check(path)
        if not folder.is_dir():
            raise HTTPException(400, "not a folder")
        dirs: list[str] = []
        files: list[str] = []
        try:
            entries = sorted(folder.iterdir(), key=lambda p: p.name.lower())[:MAX_LISTING]
        except OSError:
            raise HTTPException(403, "folder cannot be read") from None
        for entry in entries:
            try:
                if entry.is_symlink():
                    continue
                if entry.is_dir():
                    if not entry.name.startswith(".") and entry.name not in SKIP_DIRS:
                        dirs.append(entry.name)
                elif adapter_for(entry.name, folder.name) or entry.name in NOT_ANALYSED:
                    files.append(entry.name)
            except OSError:
                continue
        parent = folder.parent
        in_roots = any(parent == r or parent.is_relative_to(r) for r in settings.guard.roots)
        return {
            "path": str(folder),
            "parent": str(parent) if folder not in settings.guard.roots and in_roots else None,
            "dirs": dirs,
            "files": files,
        }

    @app.post("/api/scans")
    async def run_scan(request: Request) -> dict[str, Any]:
        try:
            body = ScanRequest.model_validate_json(await request.body())
        except ValidationError as exc:
            fields = sorted({str(e["loc"][0]) for e in exc.errors() if e.get("loc")})
            raise HTTPException(422, f"invalid request ({', '.join(fields) or 'body'})") from None
        target = settings.guard.check(body.path)
        if settings.busy:
            raise HTTPException(409, "a scan is already running")
        overrides: dict[str, object] = {}
        if body.fail_on:
            overrides["fail_on_priority"] = (
                None if body.fail_on == "none" else Priority(body.fail_on)
            )
        options = ScanOptions(
            offline=body.offline,
            cache_dir=settings.cache_dir,
            epss=body.epss,
            kev=body.kev,
            latest=body.latest,
            nvd=body.nvd,
            config_overrides=overrides,
        )

        def work() -> ScanReport:
            # Released by the worker thread itself: a thread cannot be killed, so
            # the server stays busy until the scan really ends, whatever happens
            # to the awaiting request (timeout, disconnect, loop shutdown).
            try:
                return settings.scan_fn(target, options)
            finally:
                settings.busy = False

        settings.busy = True
        task = asyncio.ensure_future(asyncio.to_thread(work))
        try:
            report = await asyncio.wait_for(asyncio.shield(task), settings.scan_timeout)
        except TimeoutError:
            raise HTTPException(504, "the scan took too long and was abandoned") from None
        except ToolError as exc:
            raise HTTPException(422, str(exc)) from None
        document = json_report.to_dict(report)
        entry = {
            "path": str(target),
            "report": document,
            "exports": {
                "json": json_report.render(report),
                "sarif": sarif.render(report),
                "cyclonedx": cyclonedx.render(
                    report.components, report.root, report.findings, report.generated_at
                ),
                "spdx": spdx.render(report.components, report.root, report.generated_at),
            },
        }
        scan_id = settings.history.add(entry)
        return {"id": scan_id, "path": str(target), "report": document}

    @app.get("/api/scans")
    async def list_scans() -> dict[str, Any]:
        return {"scans": settings.history.list()}

    def _entry(scan_id: str) -> dict[str, Any]:
        try:
            return settings.history.get(scan_id)
        except KeyError:
            raise HTTPException(404, "scan not found") from None

    @app.get("/api/scans/{scan_id}")
    async def get_scan(scan_id: str) -> dict[str, Any]:
        entry = _entry(scan_id)
        return {"id": scan_id, "path": entry["path"], "report": entry["report"]}

    @app.delete("/api/scans/{scan_id}")
    async def delete_scan(scan_id: str) -> dict[str, bool]:
        if not History.valid_id(scan_id) or not settings.history.delete(scan_id):
            raise HTTPException(404, "scan not found")
        return {"deleted": True}

    @app.get("/api/scans/{scan_id}/export/{fmt}")
    async def export(scan_id: str, fmt: str) -> Response:
        if fmt not in EXPORTS:
            raise HTTPException(404, "unknown export format")
        text = _entry(scan_id).get("exports", {}).get(fmt)
        if not isinstance(text, str):
            raise HTTPException(404, "export not available")
        filename, media = EXPORTS[fmt]
        return Response(
            text.encode("utf-8"),
            media_type=media,
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_request: Request, exc: StarletteHTTPException) -> JSONResponse:
        return _error(exc.status_code, str(exc.detail))

    index = STATIC_DIR / "local.html"
    if (STATIC_DIR / "assets").is_dir():
        app.mount("/assets", StaticFiles(directory=STATIC_DIR / "assets"), name="assets")

    @app.get("/", include_in_schema=False)
    async def home() -> Response:
        if index.is_file():
            return FileResponse(index, media_type="text/html")
        return Response(
            "<!doctype html><meta charset=utf-8><title>DepGuard</title>"
            "<p>The web interface is not built. From the repository run "
            "<code>npm ci --ignore-scripts && npm run build:local</code> in <code>web/</code>, "
            "or install a released wheel of devs-guard[web].</p>",
            media_type="text/html",
        )

    return app
