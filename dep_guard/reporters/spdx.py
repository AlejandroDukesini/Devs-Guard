"""SPDX 2.3 JSON SBOM (ISO/IEC 5962:2021 lineage) of the scanned project.

https://spdx.github.io/spdx-spec/v2.3/

Each resolved component becomes an SPDX package identified by its Package
URL (externalRefs, category PACKAGE-MANAGER). Licences and download
locations are not read from manifests, so they are `NOASSERTION`, which is
what the specification prescribes for unknown values (never a guess).
Relationships: the document DESCRIBES the root package; the root
DEPENDS_ON direct dependencies; edges recovered from dependency paths are
DEPENDS_ON; development-only packages are DEV_DEPENDENCY_OF the root.
"""

from __future__ import annotations

import datetime as dt
import json
import uuid
from pathlib import PurePath
from typing import Any

from dep_guard import __version__
from dep_guard.models import Component, Scope
from dep_guard.reporters import cyclonedx

ROOT_ID = "SPDXRef-RootPackage"
NOASSERTION = "NOASSERTION"


def to_dict(
    components: list[Component], root_name: str, timestamp: str | None = None
) -> dict[str, Any]:
    resolved = [c for c in components if c.version]
    created = timestamp or dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat()
    created = created.replace("+00:00", "Z")
    ids = {cyclonedx.full_purl(c): f"SPDXRef-Package-{i}" for i, c in enumerate(resolved, 1)}
    packages: list[dict[str, Any]] = [
        {
            "SPDXID": ROOT_ID,
            "name": root_name,
            "downloadLocation": NOASSERTION,
            "filesAnalyzed": False,
            "primaryPackagePurpose": "APPLICATION",
        }
    ]
    for c in resolved:
        packages.append(
            {
                "SPDXID": ids[cyclonedx.full_purl(c)],
                "name": c.name,
                "versionInfo": c.version,
                "downloadLocation": NOASSERTION,
                "filesAnalyzed": False,
                "licenseConcluded": NOASSERTION,
                "licenseDeclared": NOASSERTION,
                "copyrightText": NOASSERTION,
                "primaryPackagePurpose": "LIBRARY",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": cyclonedx.full_purl(c),
                    }
                ],
            }
        )

    relationships: list[dict[str, str]] = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": ROOT_ID,
        }
    ]
    dev = {cyclonedx.full_purl(c) for c in resolved if c.scope is Scope.DEV}
    for edge in cyclonedx._dependencies(resolved, "depguard:root"):
        parent = ROOT_ID if edge["ref"] == "depguard:root" else ids.get(edge["ref"])
        for child_ref in edge["dependsOn"]:
            child = ids.get(child_ref)
            if parent is None or child is None:
                continue
            if parent == ROOT_ID and child_ref in dev:
                relationships.append(
                    {
                        "spdxElementId": child,
                        "relationshipType": "DEV_DEPENDENCY_OF",
                        "relatedSpdxElement": ROOT_ID,
                    }
                )
            else:
                relationships.append(
                    {
                        "spdxElementId": parent,
                        "relationshipType": "DEPENDS_ON",
                        "relatedSpdxElement": child,
                    }
                )
    safe_name = "".join(ch if ch.isalnum() or ch in "-._" else "-" for ch in root_name) or "project"
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{root_name} dependencies",
        "documentNamespace": f"https://spdx.org/spdxdocs/depguard/{safe_name}-{uuid.uuid4()}",
        "creationInfo": {"created": created, "creators": [f"Tool: depguard-{__version__}"]},
        "packages": packages,
        "relationships": relationships,
    }


def render(components: list[Component], root: str, timestamp: str | None = None) -> str:
    doc = to_dict(components, PurePath(root).name or "project", timestamp)
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
