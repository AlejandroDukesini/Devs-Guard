"""Local web app: `depguard serve` (optional extra: pip install "devs-guard[web]")."""

from __future__ import annotations

import logging
import os
import socket
import sys
import time
import webbrowser
from collections.abc import Callable
from pathlib import Path

from dep_guard.sources.cache import default_cache_dir

DEFAULT_PORT = 8765
LOOPBACK = "127.0.0.1"


class ServeError(Exception):
    """The local server cannot start (missing extra, port in use, bad root)."""


def serve(
    roots: list[str],
    port: int = DEFAULT_PORT,
    open_browser: bool = True,
    history_dir: Path | None = None,
    cache_dir: Path | None = None,
    announce: Callable[[str], None] = print,
    token_file: Path | None = None,
) -> None:
    try:
        import uvicorn  # noqa: PLC0415 - optional extra, imported only for `serve`

        from dep_guard.server.app import Settings, create_app  # noqa: PLC0415
        from dep_guard.server.history import History  # noqa: PLC0415
        from dep_guard.server.security import PathGuard, PathRejected, new_token  # noqa: PLC0415
    except ImportError:
        raise ServeError(
            'the web interface needs the optional extra: pip install "devs-guard[web]"'
        ) from None

    try:
        guard = PathGuard.from_strings(roots)
    except (PathRejected, OSError) as exc:
        raise ServeError(f"invalid --root: {exc}") from None

    # Bind the socket ourselves: loopback only, and the real port (for --port 0)
    # is known before the Host/Origin policy is built.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((LOOPBACK, port))
    except OSError:
        sock.close()
        raise ServeError(f"port {port} is busy; try --port 0 for a free one") from None
    real_port = sock.getsockname()[1]

    _security_logging()
    token = new_token()
    settings = Settings(
        token=token,
        port=real_port,
        guard=guard,
        history=History(history_dir or default_cache_dir() / "history"),
        cache_dir=cache_dir,
    )
    app = create_app(settings)
    url = f"http://{LOOPBACK}:{real_port}/#token={token}"
    if token_file is not None:
        _write_private(token_file, url + "\n")
    announce(f"DepGuard local: {url}")
    announce(f"Allowed folders: {', '.join(guard.display_roots())}")
    announce("Only this machine can connect. Press Ctrl+C to stop.")
    config = uvicorn.Config(
        app,
        log_level="warning",
        access_log=False,
        proxy_headers=False,  # never trust X-Forwarded-* on a local tool
        server_header=False,
        limit_concurrency=32,
        timeout_keep_alive=5,
    )
    server = uvicorn.Server(config)
    if open_browser:
        webbrowser.open(url)
    server.run(sockets=[sock])


def _write_private(path: Path, text: str) -> None:
    """Write the session URL for automation (CI, e2e), readable by the user only."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)


def _security_logging() -> None:
    """Security events to stderr with UTC ISO-8601 timestamps (ASVS V16.2)."""
    handler = logging.StreamHandler(sys.stderr)
    formatter = logging.Formatter(
        "%(asctime)sZ %(levelname)s %(name)s %(message)s", datefmt="%Y-%m-%dT%H:%M:%S"
    )
    formatter.converter = time.gmtime
    handler.setFormatter(formatter)
    logger = logging.getLogger("depguard.server")
    logger.handlers[:] = [handler]
    logger.setLevel(logging.INFO)
    logger.propagate = False
