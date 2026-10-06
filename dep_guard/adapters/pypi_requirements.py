"""pip requirements files (requirements.txt, requirements-dev.txt, requirements/*.txt).

Only exact pins (`==1.2.3` / `===1.2.3`) are queried. Anything else is
reported as UNRESOLVED instead of guessing: `flask>=2.0` says nothing about
the version actually installed, and scanning 2.0 would be both a false
positive and a false negative generator. Generate a fully pinned file with
`pip freeze`, `pip-compile` or `uv export` for complete coverage.
"""

from __future__ import annotations

import re

from packaging.requirements import InvalidRequirement, Requirement

from dep_guard import purl
from dep_guard.adapters.base import ParseContext, ParseResult, location
from dep_guard.models import Component, ComponentStatus, Problem, Scope
from dep_guard.textutil import clean

_NAME = re.compile(r"(?i)^(?:.*[-_.])?requirements(?:[-_.].*)?\.txt$")
_DEV_HINT = re.compile(r"(?i)(^|[-_.])(dev|develop|tests?|testing|lint|docs?|ci)([-_.]|$)")
_INLINE_COMMENT = re.compile(r"(^|\s)#.*$")
_INCLUDE_OPTS = ("-r", "--requirement", "-c", "--constraint")
_EDITABLE_OPTS = ("-e", "--editable")


class RequirementsAdapter:
    id = "pip-requirements"

    def matches(self, filename: str, parent_dir: str) -> bool:
        if _NAME.match(filename):
            return True
        return parent_dir.lower() == "requirements" and filename.lower().endswith(".txt")

    def parse(self, content: str, ctx: ParseContext) -> ParseResult:
        result = ParseResult()
        stem = ctx.rel_path.rsplit("/", 1)[-1]
        scope = Scope.DEV if _DEV_HINT.search(stem.replace("requirements", "")) else Scope.PROD

        for lineno, line in _logical_lines(content):
            if line.startswith("-"):
                self._option(line, lineno, ctx, result)
                continue
            # Per-requirement options such as --hash come after the spec.
            spec = re.split(r"\s+--?\w", line, maxsplit=1)[0].strip()
            try:
                req = Requirement(spec)
            except InvalidRequirement:
                result.problems.append(
                    Problem(
                        "invalid_requirement",
                        f"line {lineno}: not a valid PEP 508 requirement",
                        ctx.rel_path,
                    )
                )
                continue
            result.components.append(self._component(req, scope, lineno, ctx))
        return result

    @staticmethod
    def _component(req: Requirement, scope: Scope, lineno: int, ctx: ParseContext) -> Component:
        name = purl.normalize_pypi_name(req.name)
        comp = Component(
            ecosystem="PyPI",
            name=name,
            version=None,
            purl=purl.build("PyPI", name),
            direct=True,
            scope=scope,
            locations=location(ctx, lineno),
            paths=[[name]],
        )
        specs = list(req.specifier)
        if req.url:
            comp.unresolved_reason = "direct URL reference"
        elif len(specs) == 1 and specs[0].operator in ("==", "===") and "*" not in specs[0].version:
            comp.version = specs[0].version
        elif not specs:
            comp.unresolved_reason = "no version specified"
        else:
            comp.unresolved_reason = f"not pinned ({clean(str(req.specifier), 80)})"
        if comp.version is None:
            comp.status = ComponentStatus.UNRESOLVED
        return comp

    @staticmethod
    def _option(line: str, lineno: int, ctx: ParseContext, result: ParseResult) -> None:
        opt = line.split(None, 1)[0].split("=", 1)[0]
        # Never echo option values: index URLs frequently embed credentials.
        if opt in _INCLUDE_OPTS:
            result.problems.append(
                Problem(
                    "include_not_followed",
                    f"line {lineno}: nested requirement/constraint files are not followed; "
                    "scan them directly (directory scans find them automatically)",
                    ctx.rel_path,
                )
            )
        elif opt in _EDITABLE_OPTS:
            result.problems.append(
                Problem(
                    "editable_skipped", f"line {lineno}: editable install skipped", ctx.rel_path
                )
            )


def _logical_lines(content: str) -> list[tuple[int, str]]:
    """Join backslash continuations and strip comments; keep first line number."""
    out: list[tuple[int, str]] = []
    buf, start = "", 0
    for i, raw in enumerate(content.splitlines(), start=1):
        if not buf:
            start = i
        line = raw.rstrip()
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        buf += line
        text = _INLINE_COMMENT.sub("", buf).strip()
        buf = ""
        if text:
            out.append((start, text))
    if buf.strip():
        out.append((start, _INLINE_COMMENT.sub("", buf).strip()))
    return out
