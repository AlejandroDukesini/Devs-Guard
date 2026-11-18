"""Patch verification: one remediation state per component, with its reason.

| State                      | Condition |
|----------------------------|-----------|
| unidentifiable_version     | no exact version (range, git, local path...) -> never queried |
| insufficient_data          | the OSV lookup failed, or the package is in `private_packages` |
| vulnerable_fix_available   | known advisories, and every one has a fixed version |
| vulnerable_no_fix          | known advisories, at least one without any fixed version |
| outdated                   | no known advisories, a newer stable release exists |
| up_to_date                 | no known advisories, installed >= latest stable release |
| no_known_vulnerabilities   | no known advisories, latest release not checked/comparable |

Rules that keep the answer honest:
- "latest published" is never "latest safe": when the registry's latest
  release is itself affected (checked against OSV), the note says so;
- the suggested upgrade is the *smallest* version that fixes every fixable
  advisory, and an upgrade across a major version (or a 0.x minor, which
  SemVer treats as breaking) is flagged as potentially incompatible;
- ignored findings still count: an accepted risk is a policy decision, the
  package is still vulnerable.
"""

from __future__ import annotations

import re

from dep_guard.correlate import recommended_upgrade
from dep_guard.models import Component, ComponentStatus, Finding, PatchStatus
from dep_guard.versions import compare

_LEADING = re.compile(r"^v?(\d+)(?:\.(\d+))?")


def is_breaking_upgrade(current: str | None, target: str | None) -> bool | None:
    """True when moving current -> target crosses a major (or 0.x minor) version.

    None when either version has no numeric major component.
    """
    if not current or not target:
        return None
    a, b = _LEADING.match(current.strip()), _LEADING.match(target.strip())
    if a is None or b is None:
        return None
    if int(a.group(1)) != int(b.group(1)):
        return True
    if int(a.group(1)) == 0:
        return (a.group(2) or "0") != (b.group(2) or "0")
    return False


def classify(component: Component, findings: list[Finding]) -> tuple[PatchStatus, str]:
    status = component.status
    if status is ComponentStatus.UNRESOLVED:
        return PatchStatus.UNIDENTIFIABLE_VERSION, component.unresolved_reason or "no exact version"
    if status is ComponentStatus.PRIVATE:
        return PatchStatus.INSUFFICIENT_DATA, "private package: not sent to vulnerability sources"
    if status is ComponentStatus.ERROR:
        return PatchStatus.INSUFFICIENT_DATA, f"vulnerability lookup failed: {component.error}"

    latest = component.latest
    if status is ComponentStatus.VULNERABLE and findings:
        target, fixes = recommended_upgrade(findings)
        unfixed = sum(1 for f in findings if not f.fixed_versions)
        notes: list[str] = []
        if unfixed:
            state = PatchStatus.VULNERABLE_NO_FIX
            notes.append(f"{unfixed} of {len(findings)} advisories have no fixed version")
            if target:
                notes.append(f"{target} fixes {fixes}")
        else:
            state = PatchStatus.VULNERABLE_FIX_AVAILABLE
            notes.append(f"upgrade to {target} (fixes {fixes} of {len(findings)})")
        if target and is_breaking_upgrade(component.version, target):
            notes.append("major version change: may break compatibility")
        if latest and latest == component.version:
            notes.append("already the latest release")
        elif component.latest_vulnerable is True and latest:
            notes.append(f"latest release {latest} is also affected")
        elif latest and target and (compare(component.ecosystem, target, latest) or 0) < 0:
            notes.append(f"latest release is {latest}")
        return state, "; ".join(notes)

    if not latest:
        return PatchStatus.NO_KNOWN_VULNERABILITIES, "latest release not checked"
    order = compare(component.ecosystem, component.version or "", latest)
    if order is None:
        return (
            PatchStatus.NO_KNOWN_VULNERABILITIES,
            f"latest release is {latest} (versions not comparable)",
        )
    if order >= 0:
        return PatchStatus.UP_TO_DATE, f"latest release is {latest}"
    note = f"{latest} available"
    if is_breaking_upgrade(component.version, latest):
        note += " (major version change)"
    if component.latest_vulnerable is True:
        note += f"; {latest} has known advisories"
    return PatchStatus.OUTDATED, note


def assess_all(components: list[Component], findings: list[Finding]) -> None:
    by_key: dict[str, list[Finding]] = {}
    for f in findings:
        by_key.setdefault(f.component.key, []).append(f)
    for comp in components:
        comp.patch_status, comp.patch_note = classify(comp, by_key.get(comp.key, []))
