"""Find and read manifest files safely.

Security properties:
- symlinks are never followed (neither directories nor files), so a crafted
  repository cannot make the scanner read files outside the scan root;
- vendored/third-party trees (node_modules, virtualenvs, .git...) are pruned;
- file size, file count and depth are bounded;
- only an allowlist of sibling files can be read by adapters.
"""

from __future__ import annotations

import codecs
import fnmatch
import os
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from dep_guard.adapters import SUPERSEDED_BY, Adapter, adapter_for, sniff_adapter
from dep_guard.models import Problem

MAX_FILE_BYTES = 25 * 1024 * 1024
MAX_FILES = 1000
MAX_DEPTH = 12
SIBLING_ALLOWLIST = frozenset({"pyproject.toml"})
SKIP_DIRS = frozenset(
    {
        "node_modules",
        "bower_components",
        "venv",
        "env",
        "site-packages",
        "__pycache__",
        "dist",
        "build",
        "target",
        "vendor",
    }
)


class DiscoveryError(Exception):
    """The scan target itself is unusable (missing, unreadable, unsupported)."""


@dataclass(frozen=True, slots=True)
class ManifestFile:
    path: Path
    rel_path: str  # POSIX, relative to the scan root
    adapter: Adapter


def read_text(path: Path) -> str:
    """Read a manifest as text, honouring UTF-8/UTF-16 BOMs.

    `pip freeze > requirements.txt` in Windows PowerShell 5.1 writes UTF-16,
    a common source of "empty" scans in other tools.
    """
    if path.is_symlink():
        raise DiscoveryError(f"{path.name}: symlinks are not followed")
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise DiscoveryError(f"{path.name}: file larger than {MAX_FILE_BYTES // (1024 * 1024)} MB")
    raw = path.read_bytes()
    if raw.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return raw.decode("utf-16")
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise DiscoveryError(f"{path.name}: not valid UTF-8/UTF-16 text") from None


def sibling_reader(path: Path):  # type: ignore[no-untyped-def]
    def read(name: str) -> str | None:
        if name not in SIBLING_ALLOWLIST:
            return None
        candidate = path.parent / name
        try:
            if candidate.is_file() and not candidate.is_symlink():
                return read_text(candidate)
        except (OSError, DiscoveryError):
            return None
        return None

    return read


def discover(
    target: str | Path, exclude: Iterable[str] = ()
) -> tuple[Path, list[ManifestFile], list[Problem]]:
    root = Path(target)
    if not root.exists():
        raise DiscoveryError(f"path does not exist: {target}")
    root = root.resolve()
    problems: list[Problem] = []

    if root.is_file():
        adapter = adapter_for(root.name, root.parent.name)
        if adapter is None:
            try:
                adapter = sniff_adapter(read_text(root))
            except (OSError, DiscoveryError) as exc:
                raise DiscoveryError(str(exc)) from None
        if adapter is None:
            raise DiscoveryError(
                f"unsupported file: {root.name} (see `depguard formats` for supported files)"
            )
        return root.parent, [ManifestFile(root, root.name, adapter)], problems

    patterns = list(exclude)
    found: list[ManifestFile] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        rel_dir = current.relative_to(root).as_posix()
        depth = 0 if rel_dir == "." else rel_dir.count("/") + 1
        dirnames[:] = sorted(
            d
            for d in dirnames
            if d not in SKIP_DIRS
            and not d.startswith(".")
            and depth < MAX_DEPTH
            and not (current / d).is_symlink()
        )
        names = set(filenames)
        for filename in sorted(filenames):
            adapter = adapter_for(filename, current.name)
            if adapter is None:
                continue
            if any(sup in names for sup in SUPERSEDED_BY.get(filename, ())):
                continue
            path = current / filename
            rel = path.relative_to(root).as_posix()
            if any(fnmatch.fnmatch(rel, p) for p in patterns):
                continue
            if path.is_symlink():
                problems.append(Problem("symlink_skipped", "symlinked manifest not followed", rel))
                continue
            found.append(ManifestFile(path, rel, adapter))
            if len(found) >= MAX_FILES:
                problems.append(
                    Problem("too_many_files", f"stopped after {MAX_FILES} manifest files", None)
                )
                return root, found, problems
    return root, found, problems
