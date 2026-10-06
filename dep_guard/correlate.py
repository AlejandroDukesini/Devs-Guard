"""Turn raw OSV advisories into Findings.

- Alias grouping: OSV returns the same vulnerability under several ids
  (GHSA-..., PYSEC-..., CVE-...). Ids connected through `aliases` form one
  group = one Finding, so counts are not inflated.
- Canonical id: CVE if any, else GHSA, else the first id.
- Severity: highest CVSS v3 base score computed from vectors; otherwise the
  advisory's qualitative rating; otherwise UNKNOWN (never assumed LOW).
- Fixed version: from the affected range that contains the installed version.
"""

from __future__ import annotations

import functools
from typing import Any

from dep_guard import cvss, purl
from dep_guard.models import Component, Finding, Severity
from dep_guard.textutil import clean
from dep_guard.versions import compare


def build_findings(
    component: Component,
    ids: list[str],
    records: dict[str, dict[str, Any]],
) -> list[Finding]:
    available = [i for i in ids if i in records]
    missing = [i for i in ids if i not in records]
    findings = [_finding(component, group, records) for group in _groups(available, records)]
    for vid in missing:
        findings.append(
            Finding(
                component=component,
                id=vid,
                aliases=[vid],
                summary="Advisory details unavailable (lookup failed); treat as unreviewed",
                severity=Severity.UNKNOWN,
                cvss_score=None,
                cvss_vector=None,
                cwes=[],
                fixed_versions=[],
                references=[f"https://osv.dev/vulnerability/{vid}"],
                published=None,
            )
        )
    return sorted(findings, key=lambda f: f.id)


def _groups(ids: list[str], records: dict[str, dict[str, Any]]) -> list[list[str]]:
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)

    for vid in ids:
        find(vid)
        for alias in _str_list(records[vid].get("aliases")):
            union(vid, alias)
    groups: dict[str, list[str]] = {}
    for vid in ids:
        groups.setdefault(find(vid), []).append(vid)
    return [sorted(g) for g in groups.values()]


def _canonical(all_ids: list[str]) -> str:
    for prefix in ("CVE-", "GHSA-"):
        matches = sorted(i for i in all_ids if i.startswith(prefix))
        if matches:
            return matches[0]
    return sorted(all_ids)[0]


def _finding(component: Component, group: list[str], records: dict[str, dict[str, Any]]) -> Finding:
    recs = [records[i] for i in group]
    all_ids = sorted({*group, *(a for r in recs for a in _str_list(r.get("aliases")))})

    best_score: float | None = None
    best_vector: str | None = None
    label = Severity.UNKNOWN
    cwes: set[str] = set()
    published: list[str] = []
    for rec in recs:
        for sev in rec.get("severity") or []:
            if isinstance(sev, dict) and sev.get("type") in ("CVSS_V3", "CVSS_V3_1"):
                vector = str(sev.get("score", ""))
                score = cvss.base_score_v3(vector)
                if score is not None and (best_score is None or score > best_score):
                    best_score, best_vector = score, vector
        raw_db = rec.get("database_specific")
        db: dict[str, Any] = raw_db if isinstance(raw_db, dict) else {}
        rec_label = cvss.severity_from_label(db.get("severity"))
        if rec_label.rank > label.rank:
            label = rec_label
        cwes.update(c for c in _str_list(db.get("cwe_ids")) if c.startswith("CWE-"))
        if isinstance(rec.get("published"), str):
            published.append(rec["published"])

    severity = cvss.severity_from_score(best_score) if best_score is not None else label

    return Finding(
        component=component,
        id=_canonical(all_ids),
        aliases=all_ids,
        summary=_summary(recs),
        severity=severity,
        cvss_score=best_score,
        cvss_vector=clean(best_vector, 200) if best_vector else None,
        cwes=sorted(cwes),
        fixed_versions=fixed_versions(component, recs),
        references=_references(recs),
        published=min(published) if published else None,
    )


def _summary(recs: list[dict[str, Any]]) -> str:
    ordered = sorted(
        recs, key=lambda r: (not str(r.get("id", "")).startswith("GHSA-"), r.get("id", ""))
    )
    for rec in ordered:
        if isinstance(rec.get("summary"), str) and rec["summary"].strip():
            return clean(rec["summary"], 300)
    for rec in ordered:
        details = rec.get("details")
        if isinstance(details, str) and details.strip():
            return clean(details.strip().splitlines()[0].lstrip("#").strip(), 300)
    return "No summary provided"


def _references(recs: list[dict[str, Any]]) -> list[str]:
    seen: list[str] = []
    advisory_first = sorted(
        (ref for r in recs for ref in r.get("references") or [] if isinstance(ref, dict)),
        key=lambda ref: ref.get("type") != "ADVISORY",
    )
    for ref in advisory_first:
        url = ref.get("url")
        if isinstance(url, str) and url.startswith("https://") and url not in seen:
            seen.append(clean(url, 500))
        if len(seen) >= 5:
            break
    return seen


def _matches_package(component: Component, affected: dict[str, Any]) -> bool:
    pkg = affected.get("package")
    if not isinstance(pkg, dict) or pkg.get("ecosystem") != component.ecosystem:
        return False
    name = pkg.get("name")
    if not isinstance(name, str):
        return False
    if component.ecosystem == "PyPI":
        return purl.normalize_pypi_name(name) == component.name
    return name == component.name


def fixed_versions(component: Component, recs: list[dict[str, Any]]) -> list[str]:
    version = component.version
    if version is None:
        return []
    containing: set[str] = set()
    every_fix: set[str] = set()
    eco = component.ecosystem
    for rec in recs:
        for affected in rec.get("affected") or []:
            if not isinstance(affected, dict) or not _matches_package(component, affected):
                continue
            for rng in affected.get("ranges") or []:
                if not isinstance(rng, dict) or rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                    continue
                for introduced, fixed in _intervals(rng.get("events")):
                    if fixed is None:
                        continue
                    every_fix.add(fixed)
                    lo = True if introduced == "0" else _le(eco, introduced, version)
                    hi = _lt(eco, version, fixed)
                    if lo and hi:
                        containing.add(fixed)
    candidates = containing or {f for f in every_fix if _lt(eco, version, f) is not False}
    return _sort_versions(eco, candidates)


def _intervals(events: object) -> list[tuple[str, str | None]]:
    out: list[tuple[str, str | None]] = []
    introduced: str | None = None
    for ev in events if isinstance(events, list) else []:
        if not isinstance(ev, dict):
            continue
        if isinstance(ev.get("introduced"), str):
            if introduced is not None:
                out.append((introduced, None))
            introduced = ev["introduced"]
        elif isinstance(ev.get("fixed"), str) and introduced is not None:
            out.append((introduced, ev["fixed"]))
            introduced = None
        elif isinstance(ev.get("last_affected"), str) and introduced is not None:
            out.append((introduced, None))
            introduced = None
    if introduced is not None:
        out.append((introduced, None))
    return out


def _le(eco: str, a: str, b: str) -> bool | None:
    c = compare(eco, a, b)
    return None if c is None else c <= 0


def _lt(eco: str, a: str, b: str) -> bool | None:
    c = compare(eco, a, b)
    return None if c is None else c < 0


def _sort_versions(eco: str, versions: set[str]) -> list[str]:
    def cmp(a: str, b: str) -> int:
        c = compare(eco, a, b)
        return c if c is not None else (a > b) - (a < b)

    return sorted(versions, key=functools.cmp_to_key(cmp))


def recommended_upgrade(findings: list[Finding]) -> tuple[str | None, int]:
    """Smallest single version that fixes the most findings of one component.

    Returns (version, number of findings it fixes). For each finding we take
    its lowest fix; the recommendation is the highest of those, i.e. the
    minimum upgrade that resolves every fixable finding.
    """
    if not findings:
        return None, 0
    eco = findings[0].component.ecosystem
    minimal = [f.fixed_versions[0] for f in findings if f.fixed_versions]
    if not minimal:
        return None, 0
    target = _sort_versions(eco, set(minimal))[-1]
    fixed = sum(
        1
        for f in findings
        if f.fixed_versions and (compare(eco, f.fixed_versions[0], target) or 0) <= 0
    )
    return target, fixed


def _str_list(value: object) -> list[str]:
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []
