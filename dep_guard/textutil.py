"""Sanitising text that comes from untrusted sources.

Package names come from manifests the user may not control, and advisory
summaries come from a remote database. Both end up in a terminal, in SARIF
rendered by GitHub, and in logs. Control characters (ANSI escapes, carriage
returns, bidi overrides, zero-width characters) are stripped so they cannot
forge or hide output ("Trojan Source"-style tricks).
"""

from __future__ import annotations

import re

# Code point ranges removed from untrusted text. Written as numbers on
# purpose: the source file itself must never contain invisible characters.
UNSAFE_RANGES = (
    (0x00, 0x08),  # C0 controls (tab 0x09 and newline 0x0A are kept)
    (0x0B, 0x1F),  # rest of C0, includes ESC (ANSI sequences) and CR
    (0x7F, 0x9F),  # DEL + C1 controls
    (0x200B, 0x200F),  # zero-width space/joiners, LRM, RLM
    (0x202A, 0x202E),  # bidi embeddings and overrides
    (0x2066, 0x2069),  # bidi isolates
    (0xFEFF, 0xFEFF),  # BOM / zero-width no-break space
)
_UNSAFE = re.compile(
    "[" + "".join(f"{re.escape(chr(lo))}-{re.escape(chr(hi))}" for lo, hi in UNSAFE_RANGES) + "]"
)


def clean(value: object, max_len: int = 500, single_line: bool = True) -> str:
    if not isinstance(value, str):
        return ""
    text = _UNSAFE.sub("", value)
    if single_line:
        text = " ".join(text.split())
    if len(text) > max_len:
        text = text[: max_len - 1] + "…"
    return text


def find_line(content: str, needle: str) -> int | None:
    """1-based line of the first occurrence of `needle` (best effort)."""
    idx = content.find(needle)
    if idx < 0:
        return None
    return content.count("\n", 0, idx) + 1
