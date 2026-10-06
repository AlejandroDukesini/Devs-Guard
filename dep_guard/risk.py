"""Explainable prioritisation: a decision table, not a weighted formula.

Inspired by CISA SSVC: urgency comes from *exploitation evidence* (KEV,
EPSS), *impact* (CVSS severity) and *exposure* (runtime vs development
dependency). Rules are evaluated top-down; the first match wins. Every
finding carries the reasons that produced its priority. See docs/risk-model.md.

| Priority | Rule (runtime = prod or unknown scope)                                  |
|----------|-------------------------------------------------------------------------|
| P0       | runtime AND (in KEV OR (EPSS >= threshold AND severity >= HIGH))        |
| P1       | (runtime AND severity >= HIGH) OR EPSS >= threshold OR in KEV           |
| P2       | runtime AND (severity == MEDIUM OR severity UNKNOWN); dev AND >= HIGH   |
| P3       | everything else                                                         |

Missing signals are never treated as reassuring: unknown scope counts as
runtime, unknown severity in runtime is at least P2.
"""

from __future__ import annotations

from dataclasses import dataclass

from dep_guard.models import Finding, Priority, Reason, Scope, Severity

DEFAULT_EPSS_THRESHOLD = 0.10


@dataclass(frozen=True, slots=True)
class RiskConfig:
    epss_threshold: float = DEFAULT_EPSS_THRESHOLD


DEFAULT_CONFIG = RiskConfig()


def assess(finding: Finding, config: RiskConfig = DEFAULT_CONFIG) -> None:
    comp = finding.component
    runtime = comp.scope is not Scope.DEV
    sev = finding.severity
    high = sev.rank >= Severity.HIGH.rank
    kev = finding.kev is True
    hot_epss = finding.epss is not None and finding.epss >= config.epss_threshold

    reasons: list[Reason] = []
    if kev:
        reasons.append(Reason("kev", "Explotación activa confirmada (CISA KEV)"))
    if finding.epss is not None:
        reasons.append(
            Reason(
                "epss_high" if hot_epss else "epss_low",
                f"EPSS {finding.epss:.3f} (percentil {(finding.epss_percentile or 0) * 100:.0f})",
            )
        )
    elif finding.cves:
        reasons.append(Reason("epss_unknown", "EPSS no disponible"))
    else:
        reasons.append(Reason("no_cve", "Sin CVE asignado: EPSS/KEV no aplican"))

    score = f" CVSS {finding.cvss_score}" if finding.cvss_score is not None else ""
    reasons.append(Reason(f"severity_{sev.value.lower()}", f"Severidad {sev.value}{score}"))
    if comp.scope is Scope.DEV:
        reasons.append(Reason("scope_dev", "Dependencia solo de desarrollo"))
    elif comp.scope is Scope.UNKNOWN:
        reasons.append(Reason("scope_unknown", "Ámbito desconocido: se asume runtime"))
    else:
        reasons.append(Reason("scope_prod", "Dependencia de producción"))
    if comp.direct is True:
        reasons.append(Reason("direct", "Dependencia directa"))
    elif comp.direct is False:
        via = " > ".join(comp.paths[0]) if comp.paths and comp.paths[0] else "árbol de dependencias"
        reasons.append(Reason("transitive", f"Transitiva vía {via}"))
    if finding.fixed_versions:
        reasons.append(Reason("fix_available", f"Corregida en {finding.fixed_versions[0]}"))
    else:
        reasons.append(Reason("no_fix", "Sin versión corregida publicada"))

    if runtime and (kev or (hot_epss and high)):
        priority = Priority.P0
    elif (runtime and high) or hot_epss or kev:
        priority = Priority.P1
    elif (runtime and sev in (Severity.MEDIUM, Severity.UNKNOWN)) or (not runtime and high):
        priority = Priority.P2
    else:
        priority = Priority.P3

    finding.priority = priority
    finding.reasons = reasons
