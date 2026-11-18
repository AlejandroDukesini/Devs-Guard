"""Validate DepGuard's SBOM outputs against the official JSON schemas.

    python scripts/validate_sbom.py <schema-dir>

<schema-dir> must contain the schemas published by the specification
projects (CI downloads them at pinned tags, see .github/workflows/ci.yml):
  spdx-2.3.json          spdx/spdx-spec       v2.3/schemas/spdx-schema.json
  bom-1.6.schema.json    CycloneDX/specification 1.6/schema/
  spdx.schema.json       (referenced by bom-1.6)
  jsf-0.82.schema.json   (referenced by bom-1.6)

Every fixture project is rendered in both formats; the script exits 1 if any
document violates its schema. Requires the `jsonschema` package (dev extra).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from jsonschema import validators
from referencing import Registry, Resource

from dep_guard.engine import collect
from dep_guard.reporters import cyclonedx, spdx

ROOT = Path(__file__).resolve().parent.parent
PROJECTS = sorted((ROOT / "fixtures" / "ecosystems").iterdir()) + sorted(
    p for p in (ROOT / "fixtures" / "projects").iterdir() if p.name != "malformed"
)


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def main(schema_dir: str) -> int:
    base = Path(schema_dir)
    spdx_schema = _load(base / "spdx-2.3.json")
    cdx_schema = _load(base / "bom-1.6.schema.json")
    refs = {name: _load(base / name) for name in ("spdx.schema.json", "jsf-0.82.schema.json")}
    registry: Registry = Registry().with_resources(
        [(f"http://cyclonedx.org/schema/{n}", Resource.from_contents(s)) for n, s in refs.items()]
        + [(n, Resource.from_contents(s)) for n, s in refs.items()]
    )
    failures = 0
    for project in PROJECTS:
        if not project.is_dir():
            continue
        _, components, _ = collect(project)
        documents = (
            ("SPDX 2.3", spdx.to_dict(components, project.name), spdx_schema),
            (
                "CycloneDX 1.6",
                cyclonedx.to_dict(components, project.name, [], "2099-01-01T00:00:00Z"),
                cdx_schema,
            ),
        )
        for label, doc, schema in documents:
            validator = validators.validator_for(schema)(schema, registry=registry)
            errors = list(validator.iter_errors(doc))
            failures += len(errors)
            status = "ok" if not errors else f"{len(errors)} errors"
            print(f"{project.name:18} {label:14} {status}")
            for err in errors[:5]:
                print(f"    {err.message[:160]} at {list(err.absolute_path)[:5]}")
    print(f"schema violations: {failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
