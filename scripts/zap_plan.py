"""Render .zap/plan.yaml with the session token of a running `depguard serve`.

    python scripts/zap_plan.py <token-file> <output-plan>

ZAP's Automation Framework substitutes environment variables in URLs and
job parameters but not in header values (verified with ZAP 2.17.0: the
Authorization header was sent as the literal "${DEPGUARD_TOKEN}"). The token
is therefore written into a private copy of the plan. It is read from the
file produced by `depguard serve --token-file`, so it never appears on a
command line, in the process environment or in CI logs.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

PLAN = Path(__file__).resolve().parent.parent / ".zap" / "plan.yaml"
PLACEHOLDER = "__DEPGUARD_TOKEN__"
_TOKEN = re.compile(r"#token=([A-Za-z0-9_-]{20,128})\s*$")


def main(token_file: str, output: str) -> int:
    match = _TOKEN.search(Path(token_file).read_text(encoding="utf-8"))
    if match is None:
        print("token file does not contain a DepGuard session URL", file=sys.stderr)
        return 2
    plan = PLAN.read_text(encoding="utf-8")
    if plan.count(PLACEHOLDER) < 1:
        print(f"{PLAN} has no {PLACEHOLDER} placeholder", file=sys.stderr)
        return 2
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(plan.replace(PLACEHOLDER, match.group(1)))
    print(f"plan written to {output}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1], sys.argv[2]))
