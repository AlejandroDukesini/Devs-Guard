"""Regenerate fixtures/golden/report-*.json from the Python reference engine.

    python -m tests.regen_golden

Review the git diff before committing: a golden change is a behaviour change
that the JavaScript engine must reproduce too.
"""

from __future__ import annotations

import datetime as dt
import json
import tempfile
from pathlib import Path
from typing import Any

import respx

from dep_guard.engine import ScanOptions, scan
from dep_guard.reporters import json_report
from dep_guard.sources.http import HttpClient
from tests.osv_mock import FIXTURES, install, load_state

TODAY = dt.date(2099, 1, 15)
# (golden name, project dir, config file or None)
CASES: list[tuple[str, str, str | None]] = [
    ("npm-app", "npm-app", None),
    ("npm-app-policy", "npm-app", "configs/npm-app-policy.toml"),
    ("npm-no-lock", "npm-no-lock", None),
    ("py-uv", "py-uv", None),
    ("py-poetry", "py-poetry", None),
    ("py-requirements", "py-requirements", None),
    ("sbom", "sbom", None),
    ("malformed", "malformed", None),
]
VOLATILE = ("generated_at", "stats", "tool")


def normalise(report: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in report.items() if k not in VOLATILE}


def run_case(project: str, config: str | None) -> dict[str, Any]:
    state = load_state()
    with respx.mock(assert_all_called=False) as router, tempfile.TemporaryDirectory() as cache:
        install(router, state)
        options = ScanOptions(
            today=TODAY,
            cache_dir=Path(cache),
            config_path=FIXTURES / config if config else None,
        )
        report = scan(FIXTURES / "projects" / project, options)
    return normalise(json_report.to_dict(report))


def main() -> None:
    HttpClient._backoff = lambda self, attempt: 0.0  # type: ignore[method-assign]
    for name, project, config in CASES:
        out = FIXTURES / "golden" / f"report-{name}.json"
        out.write_text(
            json.dumps(run_case(project, config), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        print(f"wrote {out.relative_to(FIXTURES.parent)}")


if __name__ == "__main__":
    main()
