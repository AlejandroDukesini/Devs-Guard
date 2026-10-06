"""Minimal Package URL (purl) helpers: https://github.com/package-url/purl-spec

Only what the scanner needs: building purls for the ecosystems we parse and
parsing purls found in CycloneDX SBOMs into an OSV (ecosystem, name) pair.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import quote, unquote

# purl type -> OSV ecosystem name. Types not listed are reported as unsupported
# instead of guessed (several, like deb/rpm, need distro context OSV requires).
PURL_TYPE_TO_ECOSYSTEM = {
    "pypi": "PyPI",
    "npm": "npm",
    "maven": "Maven",
    "golang": "Go",
    "cargo": "crates.io",
    "nuget": "NuGet",
    "gem": "RubyGems",
    "composer": "Packagist",
    "pub": "Pub",
    "hex": "Hex",
}
ECOSYSTEM_TO_PURL_TYPE = {v: k for k, v in PURL_TYPE_TO_ECOSYSTEM.items()}

_PEP503 = re.compile(r"[-_.]+")


def normalize_pypi_name(name: str) -> str:
    return _PEP503.sub("-", name).lower()


def build(ecosystem: str, name: str) -> str:
    """Versionless purl for a package."""
    ptype = ECOSYSTEM_TO_PURL_TYPE.get(ecosystem, ecosystem.lower())
    if ptype == "pypi":
        return f"pkg:pypi/{normalize_pypi_name(name)}"
    if ptype == "npm" and name.startswith("@") and "/" in name:
        scope, _, pkg = name.partition("/")
        return f"pkg:npm/{quote(scope, safe='')}/{quote(pkg, safe='')}"
    if ptype == "maven" and ":" in name:
        group, _, artifact = name.partition(":")
        return f"pkg:maven/{quote(group, safe='.')}/{quote(artifact, safe='.')}"
    return f"pkg:{ptype}/{quote(name, safe='/.')}"


@dataclass(frozen=True, slots=True)
class ParsedPurl:
    type: str
    namespace: str | None
    name: str
    version: str | None

    @property
    def ecosystem(self) -> str | None:
        return PURL_TYPE_TO_ECOSYSTEM.get(self.type)

    @property
    def osv_name(self) -> str:
        """Package name as OSV expects it for this ecosystem."""
        if not self.namespace:
            return self.name
        if self.type == "maven":
            return f"{self.namespace}:{self.name}"
        return f"{self.namespace}/{self.name}"


def parse(purl: str) -> ParsedPurl | None:
    if not isinstance(purl, str) or not purl.startswith("pkg:") or len(purl) > 2048:
        return None
    rest = purl[4:].lstrip("/")
    rest = rest.split("#", 1)[0].split("?", 1)[0]
    version: str | None = None
    if "@" in rest.rsplit("/", 1)[-1]:
        rest, _, raw_version = rest.rpartition("@")
        version = unquote(raw_version) or None
    parts = [p for p in rest.split("/") if p]
    if len(parts) < 2:
        return None
    ptype = parts[0].lower()
    name = unquote(parts[-1])
    namespace = "/".join(unquote(p) for p in parts[1:-1]) or None
    if ptype == "pypi":
        name = normalize_pypi_name(name)
    return ParsedPurl(ptype, namespace, name, version)
