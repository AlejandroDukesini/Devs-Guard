"""Small on-disk JSON cache.

Advisory details are cached by `id@modified`, so they never go stale: when
OSV updates an advisory, its `modified` timestamp changes and so does the key.
EPSS and KEV are cached for a TTL (default 24h, both are published daily).
Entries are written atomically and validated on read; a corrupt entry is a
cache miss, never an error.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


def default_cache_dir() -> Path:
    env = os.environ.get("DEPGUARD_CACHE_DIR")
    if env:
        return Path(env)
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "depguard" / "Cache"
    if sys.platform.startswith("darwin"):
        return Path.home() / "Library" / "Caches" / "depguard"
    return Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "depguard"


class Cache:
    def __init__(self, directory: str | Path | None = None, enabled: bool = True) -> None:
        self.directory = Path(directory) if directory else default_cache_dir()
        self.enabled = enabled
        self.hits = 0
        self.misses = 0

    def _file(self, namespace: str, key: str) -> Path:
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return self.directory / namespace / f"{digest}.json"

    def get(self, namespace: str, key: str, max_age: float | None = None) -> Any | None:
        if not self.enabled:
            return None
        path = self._file(namespace, key)
        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(entry, dict) or entry.get("key") != key:
                raise ValueError("mismatched entry")
            if max_age is not None and time.time() - float(entry["stored_at"]) > max_age:
                raise ValueError("expired")
        except (OSError, ValueError, KeyError, TypeError):
            self.misses += 1
            return None
        self.hits += 1
        return entry.get("value")

    def set(self, namespace: str, key: str, value: Any) -> None:
        if not self.enabled:
            return
        path = self._file(namespace, key)
        try:
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            payload = json.dumps({"key": key, "stored_at": time.time(), "value": value})
            fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
            os.replace(tmp, path)
        except OSError:
            pass  # a read-only cache directory must not break a scan

    def clear(self) -> int:
        removed = 0
        if not self.directory.exists():
            return 0
        for path in self.directory.rglob("*.json"):
            try:
                path.unlink()
                removed += 1
            except OSError:
                continue
        return removed
