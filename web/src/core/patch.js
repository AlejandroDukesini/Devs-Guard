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
    return [PatchStatus.UNIDENTIFIABLE_VERSION, component.unresolvedReason || 'no exact version']
  if (status === ComponentStatus.PRIVATE)
    return [PatchStatus.INSUFFICIENT_DATA, 'private package: not sent to vulnerability sources']
  if (status === ComponentStatus.ERROR)
    return [PatchStatus.INSUFFICIENT_DATA, `vulnerability lookup failed: ${component.error}`]

  const latest = component.latest
  if (status === ComponentStatus.VULNERABLE && findings.length) {
    const [target, fixes] = recommendedUpgrade(findings)
    const unfixed = findings.filter((f) => !f.fixedVersions.length).length
    const notes = []
    let state
    if (unfixed) {
      state = PatchStatus.VULNERABLE_NO_FIX
      notes.push(`${unfixed} of ${findings.length} advisories have no fixed version`)
      if (target) notes.push(`${target} fixes ${fixes}`)
    } else {
      state = PatchStatus.VULNERABLE_FIX_AVAILABLE
      notes.push(`upgrade to ${target} (fixes ${fixes} of ${findings.length})`)
    }
    if (target && isBreakingUpgrade(component.version, target)) notes.push('major version change: may break compatibility')
    if (latest && latest === component.version) notes.push('already the latest release')
    else if (component.latestVulnerable === true && latest) notes.push(`latest release ${latest} is also affected`)
    else if (latest && target && (compare(component.ecosystem, target, latest) ?? 0) < 0) notes.push(`latest release is ${latest}`)
    return [state, notes.join('; ')]
  }

  if (!latest) return [PatchStatus.NO_KNOWN_VULNERABILITIES, 'latest release not checked']
  const order = compare(component.ecosystem, component.version ?? '', latest)
  if (order === null) return [PatchStatus.NO_KNOWN_VULNERABILITIES, `latest release is ${latest} (versions not comparable)`]
  if (order >= 0) return [PatchStatus.UP_TO_DATE, `latest release is ${latest}`]
  let note = `${latest} available`
  if (isBreakingUpgrade(component.version, latest)) note += ' (major version change)'
  if (component.latestVulnerable === true) note += `; ${latest} has known advisories`
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
