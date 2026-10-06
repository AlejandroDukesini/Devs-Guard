"""Command line interface.

Exit codes (stable, documented in README):
  0  PASS        policy satisfied and every dependency was checked
  1  FAIL        policy violated
  2  TOOL ERROR  bad arguments, unreadable target, invalid configuration, crash
  3  INCOMPLETE  no violation found, but some dependencies could not be checked
                 (network/API failure, unparsable manifest). Never reported as PASS.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.text import Text

from dep_guard import __version__
from dep_guard.adapters import ADAPTERS
from dep_guard.engine import (
    EXIT_PASS,
    EXIT_TOOL_ERROR,
    ScanOptions,
    ToolError,
    collect,
    scan,
)
from dep_guard.models import Priority
from dep_guard.reporters import FORMATS, cyclonedx, json_report, sarif, table
from dep_guard.sources.cache import Cache

SUBCOMMANDS = {"scan", "sbom", "formats", "cache"}
SUPPORTED_FILES = {
    "npm-package-lock": "package-lock.json, npm-shrinkwrap.json (v2/v3) - transitive",
    "npm-package-json": "package.json (only when no lockfile is present) - direct only",
    "poetry-lock": "poetry.lock (+ pyproject.toml for direct/dev) - transitive",
    "uv-lock": "uv.lock - transitive",
    "pip-requirements": "requirements*.txt, requirements/*.txt - exact pins only",
    "cyclonedx-json": "*.cdx.json, bom.json, sbom.json - any purl ecosystem OSV supports",
}


class _JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return json.dumps(
            {
                "level": record.levelname.lower(),
                "logger": record.name,
                "message": record.getMessage(),
            }
        )


def _setup_logging(verbosity: int, fmt: str) -> None:
    level = logging.WARNING if verbosity == 0 else logging.INFO if verbosity == 1 else logging.DEBUG
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        _JsonLogFormatter()
        if fmt == "json"
        else logging.Formatter("%(levelname)s %(name)s: %(message)s")
    )
    root = logging.getLogger("depguard")
    root.handlers[:] = [handler]
    root.setLevel(level)
    if verbosity < 2:
        logging.getLogger("httpx").setLevel(logging.WARNING)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="depguard",
        description="Dependency vulnerability scanner with explainable prioritisation.",
    )
    parser.add_argument("--version", action="version", version=f"depguard {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="scan a directory, manifest, lockfile or CycloneDX SBOM")
    p_scan.add_argument("path", nargs="?", default=".", help="directory or file (default: .)")
    p_scan.add_argument("-f", "--format", choices=FORMATS, default="table")
    p_scan.add_argument(
        "-o", "--output", type=Path, help="write the report to a file instead of stdout"
    )
    p_scan.add_argument(
        "-c", "--config", type=Path, help="config file (default: depguard.toml in the scan root)"
    )
    p_scan.add_argument(
        "--fail-on",
        choices=[p.value for p in Priority] + ["none"],
        help="override policy.fail_on_priority",
    )
    p_scan.add_argument(
        "--offline", action="store_true", help="use only the local cache, no network"
    )
    p_scan.add_argument(
        "--no-cache", action="store_true", help="do not read or write the local cache"
    )
    p_scan.add_argument("--no-epss", action="store_true", help="do not query FIRST EPSS")
    p_scan.add_argument("--no-kev", action="store_true", help="do not query CISA KEV")
    p_scan.add_argument(
        "--allow-incomplete",
        action="store_true",
        help="exit 0 instead of 3 when some dependencies could not be checked",
    )
    _common(p_scan)

    p_sbom = sub.add_parser(
        "sbom", help="write a CycloneDX SBOM (offline, no vulnerability lookup)"
    )
    p_sbom.add_argument("path", nargs="?", default=".")
    p_sbom.add_argument("-o", "--output", type=Path)
    _common(p_sbom)

    sub.add_parser("formats", help="list supported manifest and lockfile formats")

    p_cache = sub.add_parser("cache", help="manage the local cache")
    p_cache.add_argument("action", choices=["clear", "path"])
    return parser


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("-q", "--quiet", action="store_true", help="only print the verdict line")
    p.add_argument("-v", "--verbose", action="count", default=0, help="-v info, -vv debug (stderr)")
    p.add_argument("--log-format", choices=["text", "json"], default="text")
    p.add_argument(
        "--no-color", action="store_true", help="disable colours (NO_COLOR is honoured too)"
    )


def _normalise_argv(argv: list[str]) -> list[str]:
    """Back-compat: `depguard requirements.txt` == `depguard scan requirements.txt`."""
    if argv and argv[0] not in SUBCOMMANDS and not argv[0].startswith("-"):
        return ["scan", *argv]
    return argv


def _safe_streams() -> None:
    """Never crash on output encoding (Windows cp1252 consoles, pipes in CI)."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None or (stream.encoding or "").lower().replace("-", "") == "utf8":
            continue
        if stream.isatty():
            reconfigure(errors="replace")
        else:
            reconfigure(encoding="utf-8", errors="replace")


def main(argv: list[str] | None = None) -> int:
    _safe_streams()
    args = build_parser().parse_args(_normalise_argv(list(sys.argv[1:] if argv is None else argv)))

    if args.command == "formats":
        for adapter in ADAPTERS:
            print(f"{adapter.id:18} {SUPPORTED_FILES.get(adapter.id, '')}")
        return EXIT_PASS
    if args.command == "cache":
        cache = Cache()
        if args.action == "path":
            print(cache.directory)
        else:
            print(f"removed {cache.clear()} cache entries from {cache.directory}")
        return EXIT_PASS

    _setup_logging(args.verbose, args.log_format)
    out = Console(no_color=args.no_color, soft_wrap=False)
    err = Console(stderr=True, no_color=args.no_color)
    try:
        return _run(args, out, err)
    except ToolError as exc:
        err.print(f"[bold red]error:[/bold red] {_escape(str(exc))}")
        return EXIT_TOOL_ERROR
    except KeyboardInterrupt:
        err.print("interrupted")
        return EXIT_TOOL_ERROR
    except Exception as exc:  # last-resort guard: a crash must never look like PASS
        logging.getLogger("depguard").debug("unhandled error", exc_info=True)
        err.print(
            f"[bold red]internal error:[/bold red] "
            f"{_escape(type(exc).__name__)}: {_escape(str(exc))}"
        )
        err.print(
            "re-run with -vv for a traceback and report it at "
            "https://github.com/AlejandroDukesini/Devs-Guard/issues"
        )
        return EXIT_TOOL_ERROR


def _run(args: argparse.Namespace, out: Console, err: Console) -> int:
    if args.command == "sbom":
        root, components, _problems = collect(args.path)
        _emit(cyclonedx.render(components, str(root), None, None), args.output)
        return EXIT_PASS

    if args.config is not None and not args.config.is_file():
        raise ToolError(f"config file not found: {args.config}")
    overrides: dict[str, object] = {}
    if args.fail_on:
        overrides["fail_on_priority"] = None if args.fail_on == "none" else Priority(args.fail_on)
    options = ScanOptions(
        config_path=args.config,
        offline=args.offline,
        use_cache=not args.no_cache,
        epss=False if args.no_epss else None,
        kev=False if args.no_kev else None,
        allow_incomplete=args.allow_incomplete,
        config_overrides=overrides,
    )
    if not args.quiet and args.format == "table" and args.output is None:
        err.print(Text(f"Escaneando {args.path}…", style="dim"))
    report = scan(args.path, options)

    if args.format == "table":
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open("w", encoding="utf-8") as fh:
                table.render(report, Console(file=fh, no_color=True, width=140), quiet=args.quiet)
        else:
            table.render(report, out, quiet=args.quiet)
        return report.exit_code

    if args.format == "json":
        text = json_report.render(report)
    elif args.format == "sarif":
        text = sarif.render(report)
    else:
        text = cyclonedx.render(
            report.components, report.root, report.findings, report.generated_at
        )
    _emit(text, args.output)
    if not args.quiet:
        err.print(Text(f"DepGuard: {report.policy.verdict.value} (exit {report.exit_code})"))
    return report.exit_code


def _emit(text: str, output: Path | None) -> None:
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
    else:
        # Bytes, not text: the Windows console codepage must not corrupt or
        # crash machine-readable output.
        sys.stdout.flush()
        sys.stdout.buffer.write(text.encode("utf-8"))
        sys.stdout.buffer.flush()


def _escape(text: str) -> str:
    return escape(text)


if __name__ == "__main__":
    sys.exit(main())
