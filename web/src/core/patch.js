// Patch verification: one remediation state per component. Mirrors
// dep_guard/patch.py (same states, same notes); the shared goldens compare them.
// The browser demo does not query package registries, so `latest` stays null
// and clean packages are reported as no_known_vulnerabilities.

import { recommendedUpgrade } from './correlate.js'
import { ComponentStatus, componentKey } from './models.js'
import { compare } from './versions.js'

export const PatchStatus = Object.freeze({
  UP_TO_DATE: 'up_to_date',
  OUTDATED: 'outdated',
  VULNERABLE_FIX_AVAILABLE: 'vulnerable_fix_available',
  VULNERABLE_NO_FIX: 'vulnerable_no_fix',
  NO_KNOWN_VULNERABILITIES: 'no_known_vulnerabilities',
  INSUFFICIENT_DATA: 'insufficient_data',
  UNIDENTIFIABLE_VERSION: 'unidentifiable_version',
})
export const PATCH_STATUSES = Object.values(PatchStatus)

const LEADING = /^v?(\d+)(?:\.(\d+))?/

/** True when current -> target crosses a major (or 0.x minor) version; null if unknown. */
export function isBreakingUpgrade(current, target) {
  if (!current || !target) return null
  const a = LEADING.exec(current.trim())
  const b = LEADING.exec(target.trim())
  if (!a || !b) return null
  if (Number(a[1]) !== Number(b[1])) return true
  if (Number(a[1]) === 0) return (a[2] ?? '0') !== (b[2] ?? '0')
  return false
}

export function classify(component, findings) {
  const status = component.status
  if (status === ComponentStatus.UNRESOLVED)
    return [PatchStatus.UNIDENTIFIABLE_VERSION, component.unresolvedReason || 'sin versión exacta']
  if (status === ComponentStatus.PRIVATE)
    return [PatchStatus.INSUFFICIENT_DATA, 'paquete privado: no se envía a las fuentes de vulnerabilidades']
  if (status === ComponentStatus.ERROR)
    return [PatchStatus.INSUFFICIENT_DATA, `falló la consulta de vulnerabilidades: ${component.error}`]

  const latest = component.latest
  if (status === ComponentStatus.VULNERABLE && findings.length) {
    const [target, fixes] = recommendedUpgrade(findings)
    const unfixed = findings.filter((f) => !f.fixedVersions.length).length
    const notes = []
    let state
    if (unfixed) {
      state = PatchStatus.VULNERABLE_NO_FIX
      notes.push(`${unfixed} de ${findings.length} avisos sin versión corregida`)
      if (target) notes.push(`${target} corrige ${fixes}`)
    } else {
      state = PatchStatus.VULNERABLE_FIX_AVAILABLE
      notes.push(`actualizar a ${target} (corrige ${fixes} de ${findings.length})`)
    }
    if (target && isBreakingUpgrade(component.version, target)) notes.push('cambio de versión mayor: puede romper la compatibilidad')
    if (latest && latest === component.version) notes.push('ya es la última versión publicada')
    else if (component.latestVulnerable === true && latest) notes.push(`la última versión ${latest} también está afectada`)
    else if (latest && target && (compare(component.ecosystem, target, latest) ?? 0) < 0) notes.push(`la última versión es ${latest}`)
    return [state, notes.join('; ')]
  }

  if (!latest)
    return [
      PatchStatus.NO_KNOWN_VULNERABILITIES,
      component.latestNote ? `última versión desconocida: ${component.latestNote}` : 'última versión no consultada',
    ]
  const order = compare(component.ecosystem, component.version ?? '', latest)
  if (order === null) return [PatchStatus.NO_KNOWN_VULNERABILITIES, `la última versión es ${latest} (versiones no comparables)`]
  // Newer than the latest stable release: pre-release or never published.
  if (order > 0)
    return [PatchStatus.NO_KNOWN_VULNERABILITIES, `posterior a la última versión estable (${latest}): pre-release o no publicada`]
  if (order === 0) return [PatchStatus.UP_TO_DATE, `la última versión es ${latest}`]
  let note = `${latest} disponible`
  if (isBreakingUpgrade(component.version, latest)) note += ' (cambio de versión mayor)'
  if (component.latestVulnerable === true) note += `; ${latest} tiene avisos conocidos`
  return [PatchStatus.OUTDATED, note]
}

export function assessAll(components, findings) {
  const byKey = new Map()
  for (const f of findings) {
    const key = componentKey(f.component)
    if (!byKey.has(key)) byKey.set(key, [])
    byKey.get(key).push(f)
  }
  for (const c of components) {
    const [state, note] = classify(c, byKey.get(componentKey(c)) ?? [])
    c.patchStatus = state
    c.patchNote = note
  }
}
