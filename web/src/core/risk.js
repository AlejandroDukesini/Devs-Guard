// Explainable prioritisation (decision table). Mirrors dep_guard/risk.py and
// docs/risk-model.md. Reason texts are identical to the Python engine.

import { Scope, Severity, pyFixed, pyFloat, severityRank } from './models.js'
import { findingCves } from './correlate.js'

export const DEFAULT_EPSS_THRESHOLD = 0.1

export function assess(finding, { epssThreshold = DEFAULT_EPSS_THRESHOLD } = {}) {
  const comp = finding.component
  const runtime = comp.scope !== Scope.DEV
  const sev = finding.severity
  const high = severityRank(sev) >= severityRank(Severity.HIGH)
  const kev = finding.kev === true
  const hotEpss = finding.epss !== null && finding.epss >= epssThreshold

  const reasons = []
  const add = (code, text) => reasons.push({ code, text })
  if (kev) add('kev', 'Explotación activa confirmada (CISA KEV)')
  if (finding.epss !== null) {
    add(
      hotEpss ? 'epss_high' : 'epss_low',
      `EPSS ${pyFixed(finding.epss, 3)} (percentil ${pyFixed((finding.epssPercentile ?? 0) * 100, 0)})`,
    )
  } else if (findingCves(finding).length) add('epss_unknown', 'EPSS no disponible')
  else add('no_cve', 'Sin CVE asignado: EPSS/KEV no aplican')

  const score = finding.cvssScore !== null ? ` CVSS ${pyFloat(finding.cvssScore)}` : ''
  add(`severity_${sev.toLowerCase()}`, `Severidad ${sev}${score}`)
  if (comp.scope === Scope.DEV) add('scope_dev', 'Dependencia solo de desarrollo')
  else if (comp.scope === Scope.UNKNOWN) add('scope_unknown', 'Ámbito desconocido: se asume runtime')
  else add('scope_prod', 'Dependencia de producción')
  if (comp.direct === true) add('direct', 'Dependencia directa')
  else if (comp.direct === false) {
    const via = comp.paths.length && comp.paths[0].length ? comp.paths[0].join(' > ') : 'árbol de dependencias'
    add('transitive', `Transitiva vía ${via}`)
  }
  if (finding.fixedVersions.length) add('fix_available', `Corregida en ${finding.fixedVersions[0]}`)
  else add('no_fix', 'Sin versión corregida publicada')

  let priority
  if (runtime && (kev || (hotEpss && high))) priority = 'P0'
  else if ((runtime && high) || hotEpss || kev) priority = 'P1'
  else if ((runtime && [Severity.MEDIUM, Severity.UNKNOWN].includes(sev)) || (!runtime && high)) priority = 'P2'
  else priority = 'P3'

  finding.priority = priority
  finding.reasons = reasons
}
