"""Scan history of the local app: one JSON file per scan, newest kept.

Stored next to the cache (`<cache dir>/history`, or `--history-dir`). Each
entry keeps the report and its exports rendered at scan time, so exporting
later gives exactly what was shown. Ids are random hex strings validated
before they are used to build a file name.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import tempfile
import threading
from pathlib import Path
from typing import Any

MAX_ENTRIES = 50
_ID = re.compile(r"^[0-9a-f]{16}$")


class History:
    def __init__(self, directory: Path, max_entries: int = MAX_ENTRIES) -> None:
        self.directory = directory
        self.max_entries = max_entries
        self._lock = threading.Lock()

    @staticmethod
    def valid_id(scan_id: str) -> bool:
        return bool(_ID.match(scan_id))

    def _path(self, scan_id: str) -> Path:
        if not self.valid_id(scan_id):
            raise KeyError(scan_id)
        return self.directory / f"{scan_id}.json"

    def add(self, entry: dict[str, Any]) -> str:
        scan_id = secrets.token_hex(8)
        with self._lock:
            self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd, tmp = tempfile.mkstemp(dir=self.directory, suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump({"id": scan_id, **entry}, fh, ensure_ascii=False)
            os.replace(tmp, self._path(scan_id))
            self._prune()
        return scan_id

    def _prune(self) -> None:
        files = sorted(self.directory.glob("*.json"), key=lambda p: p.stat().st_mtime)
        for old in files[: max(0, len(files) - self.max_entries)]:
            old.unlink(missing_ok=True)

    def get(self, scan_id: str) -> dict[str, Any]:
        path = self._path(scan_id)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise KeyError(scan_id) from None
        if not isinstance(data, dict) or data.get("id") != scan_id:
            raise KeyError(scan_id)
        return data

    def delete(self, scan_id: str) -> bool:
        path = self._path(scan_id)
        with self._lock:
            if path.is_file():
                path.unlink()
                return True
        return False

    def list(self) -> list[dict[str, Any]]:
        if not self.directory.is_dir():
            return []
        out: list[dict[str, Any]] = []
        for path in sorted(
            self.directory.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True
        ):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                report = data["report"]
                out.append(
                    {
                        "id": data["id"],
                        "path": data["path"],
                        "scanned_at": report["generated_at"],
                        "verdict": report["verdict"],
                        "by_priority": report["summary"]["by_priority"],
                        "components": report["summary"]["components"],
                        "findings": report["summary"]["findings"],
                    }
                )
            except (OSError, ValueError, KeyError, TypeError):
                continue  # a corrupt entry is skipped, never fatal
        return out
