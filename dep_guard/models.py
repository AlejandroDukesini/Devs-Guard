"""Core data model shared by adapters, sources, risk, policy and reporters.

Everything here is plain data. Identity of a dependency is its Package URL
(purl) without version plus the version, so the same package declared in two
manifests is merged into one Component with several locations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Scope(StrEnum):
    PROD = "prod"
    DEV = "dev"
    UNKNOWN = "unknown"


class ComponentStatus(StrEnum):
    """What we know about a component after the scan.

    The distinction between CLEAN and ERROR/UNRESOLVED is the point of this
    tool: "no vulnerabilities found" and "could not determine" are never the
    same answer.
    """

    CLEAN = "clean"  # queried successfully, no known advisories
    VULNERABLE = "vulnerable"  # queried successfully, advisories found
    UNRESOLVED = "unresolved"  # no exact version (range, URL, git...) -> not queried
    PRIVATE = "private"  # matched private_packages -> deliberately not sent to OSV
    ERROR = "error"  # query failed -> status unknown


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.UNKNOWN: 0,
}


class Priority(StrEnum):
    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"

    @property
    def rank(self) -> int:
        # Lower number = more urgent.
        return int(self.value[1])


class FindingStatus(StrEnum):
    ACTIVE = "active"
    IGNORED = "ignored"


@dataclass(frozen=True, slots=True)
class Location:
    file: str  # path relative to the scan root, POSIX separators
    line: int | None = None


@dataclass(slots=True)
class Component:
    ecosystem: str  # OSV ecosystem name ("PyPI", "npm") or purl type for SBOM input
    name: str
    version: str | None
    purl: str  # without version, e.g. pkg:pypi/requests
    direct: bool | None = None  # None = unknown (no manifest/graph information)
    scope: Scope = Scope.UNKNOWN
    locations: list[Location] = field(default_factory=list)
    paths: list[list[str]] = field(default_factory=list)  # root -> ... -> this package
    unresolved_reason: str | None = None
    status: ComponentStatus = ComponentStatus.CLEAN
    error: str | None = None

    @property
    def key(self) -> str:
        return f"{self.purl}@{self.version or ''}"

    @property
    def purl_with_version(self) -> str:
        return f"{self.purl}@{self.version}" if self.version else self.purl


@dataclass(slots=True)
class Reason:
    code: str
    text: str


@dataclass(slots=True)
class Finding:
    """One vulnerability (alias group) affecting one component."""

    component: Component
    id: str  # canonical id: CVE > GHSA > others
    aliases: list[str]  # every id in the group, sorted, including `id`
    summary: str
    severity: Severity
    cvss_score: float | None
    cvss_vector: str | None
    cwes: list[str]
    fixed_versions: list[str]  # candidate fixes for the installed version
    references: list[str]
    published: str | None
    epss: float | None = None
    epss_percentile: float | None = None
    kev: bool | None = None  # None = KEV not checked
    priority: Priority = Priority.P3
    reasons: list[Reason] = field(default_factory=list)
    status: FindingStatus = FindingStatus.ACTIVE
    ignore_reason: str | None = None
    ignore_expires: str | None = None

    @property
    def cves(self) -> list[str]:
        return [a for a in self.aliases if a.startswith("CVE-")]


@dataclass(slots=True)
class Problem:
    """A warning or error that is part of the result, not an exception."""

    code: str
    message: str
    file: str | None = None
