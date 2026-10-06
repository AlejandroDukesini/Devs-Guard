"""Security properties of the scanner itself."""

from __future__ import annotations

import ast
import asyncio
import os
from pathlib import Path

import httpx
import pytest

from dep_guard.discovery import MAX_FILE_BYTES, DiscoveryError, discover, read_text
from dep_guard.sources.cache import Cache
from dep_guard.sources.http import HttpClient, SourceError
from dep_guard.textutil import clean

PACKAGE = Path(__file__).resolve().parent.parent / "dep_guard"


def test_no_code_execution_primitives_in_package() -> None:
    """The scanner parses manifests; it must never execute anything from them."""
    banned_calls = {"eval", "exec", "compile", "__import__"}
    banned_modules = {"subprocess", "pickle", "marshal", "shelve", "os.system"}
    for path in PACKAGE.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in banned_calls, f"{path.name}: {node.func.id}()"
            if isinstance(node, ast.Import | ast.ImportFrom):
                names = [a.name for a in node.names] + [getattr(node, "module", "") or ""]
                assert not banned_modules & set(names), f"{path.name}: imports {names}"
            if isinstance(node, ast.Attribute) and node.attr in {"system", "popen"}:
                pytest.fail(f"{path.name}: os.{node.attr}")


def test_control_characters_and_bidi_are_stripped() -> None:
    hostile = "ok" + chr(0x1B) + "[31mred" + chr(0x07) + chr(0x202E) + "hid" + chr(0x200B) + "den"
    assert clean(hostile) == "ok[31mredhidden"
    assert clean("a" * 600, max_len=10).endswith("…")
    assert clean(None) == ""


@pytest.mark.skipif(
    os.name == "nt", reason="creating symlinks needs privileges on Windows; covered on Linux CI"
)
def test_symlinks_are_not_followed(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "requirements.txt").write_text("secret==1.0\n")
    root = tmp_path / "repo"
    root.mkdir()
    (root / "linked").symlink_to(outside, target_is_directory=True)
    (root / "requirements.txt").symlink_to(outside / "requirements.txt")
    _, files, problems = discover(root)
    assert files == []
    assert any(p.code == "symlink_skipped" for p in problems)


def test_vendored_and_hidden_directories_are_pruned(tmp_path: Path) -> None:
    for d in ("node_modules/x", ".git", "venv", "src"):
        (tmp_path / d).mkdir(parents=True)
    for d in ("node_modules/x", ".git", "venv", "src"):
        (tmp_path / d / "requirements.txt").write_text("a==1\n")
    _, files, _ = discover(tmp_path)
    assert [f.rel_path for f in files] == ["src/requirements.txt"]


def test_lockfile_supersedes_manifest(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "package-lock.json").write_text('{"lockfileVersion": 3, "packages": {}}')
    _, files, _ = discover(tmp_path)
    assert [f.rel_path for f in files] == ["package-lock.json"]


def test_oversized_file_is_refused(tmp_path: Path) -> None:
    big = tmp_path / "requirements.txt"
    with big.open("wb") as fh:
        fh.seek(MAX_FILE_BYTES + 1)
        fh.write(b"\0")
    with pytest.raises(DiscoveryError, match="larger than"):
        read_text(big)


def test_utf16_requirements_from_powershell(tmp_path: Path) -> None:
    path = tmp_path / "requirements.txt"
    path.write_bytes("requests==2.20.0\r\n".encode("utf-16"))
    assert read_text(path).strip() == "requests==2.20.0"


def test_binary_garbage_is_a_controlled_error(tmp_path: Path) -> None:
    path = tmp_path / "requirements.txt"
    path.write_bytes(b"\xff\xfe\xfa\x00\xc3\x28")
    path.write_bytes(b"\xc3\x28\xa0\xa1")
    with pytest.raises(DiscoveryError, match="not valid"):
        read_text(path)


def test_missing_target(tmp_path: Path) -> None:
    with pytest.raises(DiscoveryError, match="does not exist"):
        discover(tmp_path / "nope")


def _get(url: str, transport: httpx.MockTransport | None = None, max_bytes: int = 10_000) -> object:
    async def run() -> object:
        async with httpx.AsyncClient(transport=transport, follow_redirects=False) as client:
            return await HttpClient(client, max_bytes=max_bytes).get_json(url)

    return asyncio.run(run())


@pytest.mark.parametrize(
    "url", ["https://evil.example/x", "http://api.osv.dev/v1/query", "file:///etc/passwd"]
)
def test_http_refuses_non_allowlisted_hosts(url: str) -> None:
    with pytest.raises(SourceError, match="non-allowlisted"):
        _get(url)


def test_http_caps_response_size() -> None:
    transport = httpx.MockTransport(
        lambda r: httpx.Response(200, content=b"[" + b"1," * 5000 + b"1]")
    )
    with pytest.raises(SourceError, match="size limit"):
        _get("https://api.osv.dev/v1/vulns/X", transport, max_bytes=1000)


def test_http_does_not_follow_redirects() -> None:
    transport = httpx.MockTransport(
        lambda r: httpx.Response(302, headers={"Location": "https://evil.example/"})
    )
    with pytest.raises(SourceError, match="HTTP 302"):
        _get("https://api.osv.dev/v1/vulns/X", transport)


def test_corrupt_cache_entry_is_a_miss(tmp_path: Path) -> None:
    cache = Cache(tmp_path)
    cache.set("ns", "k", {"v": 1})
    assert cache.get("ns", "k") == {"v": 1}
    for f in (tmp_path / "ns").glob("*.json"):
        f.write_text("{not json")
    assert cache.get("ns", "k") is None


def test_cache_entry_for_other_key_is_rejected(tmp_path: Path) -> None:
    cache = Cache(tmp_path)
    cache.set("ns", "a", 1)
    src = next((tmp_path / "ns").glob("*.json"))
    target = cache._file("ns", "b")
    target.write_text(src.read_text())  # simulate collision / tampering
    assert cache.get("ns", "b") is None
