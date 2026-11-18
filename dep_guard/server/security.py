"""Security controls of the local web app (`depguard serve`).

Threat model: the server runs on the user's machine with the user's file
permissions. Any web page the user visits can try to reach it (it listens
on a loopback port), so every request is treated as hostile until proven
to come from the DepGuard page opened by the user.

1. Network exposure: the socket binds to 127.0.0.1 only (enforced in
   `serve`, no option to change it).
2. Authentication: a random per-session token (256 bits) is required in the
   `Authorization: Bearer` header of every API call. It is never stored in a
   cookie, so the browser never attaches it automatically (no CSRF), and a
   cross-origin page cannot send that header without a CORS preflight, which
   this server never approves (no CORS headers at all).
3. DNS rebinding: the Host header must be exactly 127.0.0.1:<port> or
   localhost:<port>; a rebinding page arrives with its own host name.
4. Origin: when a browser sends Origin, it must be this server's origin.
5. File access: scans and folder browsing are limited to the allowed roots
   (default: the user's home). Paths are validated lexically *before* the
   file system is touched (UNC / device paths are refused: resolving
   \\\\host\\share on Windows sends the user's NTLM credentials to that
   host), then resolved and checked again, so symlinks and junctions cannot
   escape a root.
"""

from __future__ import annotations

import hmac
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path, PurePath, PurePosixPath, PureWindowsPath

MAX_PATH_CHARS = 4096
TOKEN_BYTES = 32


class PathRejected(Exception):
    """The requested path is outside the allowed roots or not acceptable."""


def new_token() -> str:
    return secrets.token_urlsafe(TOKEN_BYTES)


def token_matches(expected: str, header: str | None) -> bool:
    if not header or not header.startswith("Bearer "):
        return False
    return hmac.compare_digest(expected.encode(), header[7:].strip().encode())


@dataclass(slots=True)
class OriginPolicy:
    port: int
    hosts: frozenset[str] = field(init=False)
    origins: frozenset[str] = field(init=False)

    def __post_init__(self) -> None:
        names = ("127.0.0.1", "localhost")
        self.hosts = frozenset(f"{n}:{self.port}" for n in names)
        self.origins = frozenset(f"http://{n}:{self.port}" for n in names)

    def host_ok(self, host: str | None) -> bool:
        return (host or "").lower() in self.hosts

    def origin_ok(self, origin: str | None) -> bool:
        # Same-origin GETs may omit Origin; any Origin that is present must match.
        return origin is None or origin.lower() in self.origins


def _pure(path: str) -> PurePath:
    return PureWindowsPath(path) if os.name == "nt" else PurePosixPath(path)


def _lexically_inside(candidate: PurePath, root: PurePath) -> bool:
    if os.name == "nt":
        c = [p.lower() for p in candidate.parts]
        r = [p.lower() for p in root.parts]
    else:
        c, r = list(candidate.parts), list(root.parts)
    return c[: len(r)] == r


@dataclass(slots=True)
class PathGuard:
    roots: list[Path]

    @classmethod
    def from_strings(cls, roots: list[str]) -> PathGuard:
        resolved: list[Path] = []
        for raw in roots:
            root = Path(raw).expanduser().resolve(strict=True)
            if not root.is_dir():
                raise PathRejected(f"allowed root is not a directory: {raw}")
            resolved.append(root)
        if not resolved:
            raise PathRejected("at least one allowed root is required")
        return cls(resolved)

    def check(self, raw: str) -> Path:
        """Return the resolved path if it is inside an allowed root, else raise."""
        if not isinstance(raw, str) or not raw.strip():
            raise PathRejected("path is required")
        if len(raw) > MAX_PATH_CHARS or "\x00" in raw:
            raise PathRejected("path is not acceptable")
        text = raw.strip()
        if text.startswith(("\\\\", "//")):
            raise PathRejected("network and device paths are not allowed")
        pure = _pure(text)
        if not pure.is_absolute():
            raise PathRejected("path must be absolute")
        if ".." in pure.parts:
            raise PathRejected("path must not contain '..'")
        if not any(_lexically_inside(pure, _pure(str(r))) for r in self.roots):
            raise PathRejected("path is outside the allowed folders")
        try:
            resolved = Path(text).resolve(strict=True)
        except (OSError, RuntimeError):
            raise PathRejected("path does not exist or cannot be read") from None
        if not any(resolved == r or resolved.is_relative_to(r) for r in self.roots):
            raise PathRejected("path resolves outside the allowed folders")
        return resolved

    def display_roots(self) -> list[str]:
        return [str(r) for r in self.roots]
