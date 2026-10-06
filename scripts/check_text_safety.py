"""Fail if any tracked text file contains invisible or bidi control characters.

Guards against "Trojan Source" (CVE-2021-42574) style changes, where code
renders differently from how it is compiled. Run in CI:

    python scripts/check_text_safety.py
"""

from __future__ import annotations

import subprocess  # nosec B404 - fixed git command, no user input
import sys
from pathlib import Path

# Same code points that dep_guard/textutil.py strips from untrusted text,
# minus tab/LF/CR which are legitimate in source files.
FORBIDDEN = {
    *range(0x00, 0x09),
    0x0B,
    0x0C,
    *range(0x0E, 0x20),
    0x7F,
    *range(0x200B, 0x2010),
    *range(0x202A, 0x202F),
    *range(0x2066, 0x206A),
    0xFEFF,
}


def main() -> int:
    # Constant argv, no shell, no user input.
    files = subprocess.run(  # nosec B603 B607
        ["git", "ls-files", "-z"], capture_output=True, check=True
    ).stdout.split(b"\0")
    bad = 0
    for raw in filter(None, files):
        path = raw.decode()
        try:
            text = Path(path).read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
            continue  # binary or removed file
        for lineno, line in enumerate(text.splitlines(), 1):
            hits = sorted({f"U+{ord(c):04X}" for c in line if ord(c) in FORBIDDEN})
            if hits:
                bad += 1
                print(f"{path}:{lineno}: forbidden character(s) {', '.join(hits)}")
    if bad:
        print(f"\n{bad} line(s) with invisible/bidi control characters. Use escapes instead.")
        return 1
    print("text safety: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
