"""SPDX 2.3 output: identifiers, relationships and CLI integration.

Full validation against the official JSON schema runs in CI
(scripts/validate_sbom.py); these tests pin the semantics offline.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from dep_guard.cli import main
from dep_guard.engine import collect
from dep_guard.reporters import spdx
from tests.osv_mock import FIXTURES

SPDX_ID = re.compile(r"^SPDXRef-[A-Za-z0-9.-]+$")


def _doc(project: str) -> dict[str, object]:
    _, components, _ = collect(FIXTURES / "ecosystems" / project)
    return spdx.to_dict(components, project, "2099-01-01T00:00:00+00:00")


def test_identifiers_are_unique_valid_and_every_relationship_resolves() -> None:
    doc = _doc("pnpm-v9")
    packages = doc["packages"]
    assert isinstance(packages, list)
    ids = [p["SPDXID"] for p in packages]
    assert len(ids) == len(set(ids)) and all(SPDX_ID.match(i) for i in ids)
    known = {*ids, "SPDXRef-DOCUMENT"}
    relationships = doc["relationships"]
    assert isinstance(relationships, list)
    for rel in relationships:
        assert rel["spdxElementId"] in known and rel["relatedSpdxElement"] in known
    assert doc["creationInfo"] == {
        "created": "2099-01-01T00:00:00Z",
        "creators": [f"Tool: depguard-{__import__('dep_guard').__version__}"],
    }


def test_unresolved_versions_are_not_listed_and_unknowns_are_noassertion() -> None:
    doc = _doc("pnpm-v9")
    names = {p["name"] for p in doc["packages"]}  # type: ignore[union-attr]
    assert "lodash-es" not in names  # git tarball: no registry version
    lib = next(p for p in doc["packages"] if p["name"] == "react")  # type: ignore[union-attr]
    assert lib["licenseConcluded"] == lib["downloadLocation"] == "NOASSERTION"
    assert lib["externalRefs"][0]["referenceLocator"] == "pkg:npm/react@18.2.0"


def test_graph_relationships_and_dev_dependencies() -> None:
    doc = _doc("pnpm-v9")
    by_id = {p["SPDXID"]: p["name"] for p in doc["packages"]}  # type: ignore[union-attr]
    rels = {
        (
            by_id.get(r["spdxElementId"], r["spdxElementId"]),
            r["relationshipType"],
            by_id.get(r["relatedSpdxElement"], r["relatedSpdxElement"]),
        )
        for r in doc["relationships"]  # type: ignore[union-attr]
    }
    assert ("SPDXRef-DOCUMENT", "DESCRIBES", "pnpm-v9") in rels
    assert ("pnpm-v9", "DEPENDS_ON", "react-dom") in rels
    assert ("react-dom", "DEPENDS_ON", "loose-envify") in rels
    assert ("vitest", "DEV_DEPENDENCY_OF", "pnpm-v9") in rels


def test_documents_namespaces_are_unique() -> None:
    assert _doc("go")["documentNamespace"] != _doc("go")["documentNamespace"]


@pytest.mark.parametrize("project", ["cargo", "maven"])
def test_sbom_command_writes_spdx(project: str, tmp_path: Path) -> None:
    out = tmp_path / "sbom.spdx.json"
    assert main(["sbom", str(FIXTURES / "ecosystems" / project), "-f", "spdx", "-o", str(out)]) == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["spdxVersion"] == "SPDX-2.3"
    assert len(doc["packages"]) > 1
