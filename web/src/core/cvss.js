// CVSS v3.x base score (FIRST v3.1 spec, section 7). Mirrors dep_guard/cvss.py.
// v4 vectors are not scored: an explicit "unknown" beats a wrong number.

import { Severity } from './models.js'

const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }
const AC = { L: 0.77, H: 0.44 }
const PR_UNCHANGED = { N: 0.85, L: 0.62, H: 0.27 }
const PR_CHANGED = { N: 0.85, L: 0.68, H: 0.5 }
const UI = { N: 0.85, R: 0.62 }
const CIA = { H: 0.56, L: 0.22, N: 0 }
const REQUIRED = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']
const has = (obj, key) => Object.hasOwn(obj, key)

/** Python's round(): half to even. */
function roundHalfEven(x) {
  const r = Math.round(x)
  return Math.abs(x % 1) === 0.5 && r % 2 !== 0 ? r - 1 : r
}

export function roundup(value) {
  const intInput = roundHalfEven(value * 100000)
  if (intInput % 10000 === 0) return intInput / 100000
  return (Math.floor(intInput / 10000) + 1) / 10
}

export function parseVector(vector) {
  const parts = String(vector).trim().split('/')
  if (!parts[0].startsWith('CVSS:3.')) return null
  const metrics = {}
  for (const part of parts.slice(1)) {
    if (!part.includes(':')) return null
    const i = part.indexOf(':')
    const key = part.slice(0, i)
    if (has(metrics, key)) return null
    metrics[key] = part.slice(i + 1)
  }
  return REQUIRED.every((k) => has(metrics, k)) ? metrics : null
}

export function baseScoreV3(vector) {
  const m = parseVector(vector)
  if (!m || !['U', 'C'].includes(m.S)) return null
  const changed = m.S === 'C'
  const pr = (changed ? PR_CHANGED : PR_UNCHANGED)[m.PR]
  const values = [AV[m.AV], AC[m.AC], UI[m.UI], pr, CIA[m.C], CIA[m.I], CIA[m.A]]
  if (values.some((v) => v === undefined)) return null
  const [av, ac, ui, , c, i, a] = values

  const iss = 1 - (1 - c) * (1 - i) * (1 - a)
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss
  const exploitability = 8.22 * av * ac * pr * ui
  if (impact <= 0) return 0
  return changed
    ? roundup(Math.min(1.08 * (impact + exploitability), 10))
    : roundup(Math.min(impact + exploitability, 10))
}

export function severityFromScore(score) {
  if (score >= 9) return Severity.CRITICAL
  if (score >= 7) return Severity.HIGH
  if (score >= 4) return Severity.MEDIUM
  return Severity.LOW
}

const QUALITATIVE = { CRITICAL: 'CRITICAL', HIGH: 'HIGH', MODERATE: 'MEDIUM', MEDIUM: 'MEDIUM', LOW: 'LOW' }

export function severityFromLabel(label) {
  if (typeof label !== 'string') return Severity.UNKNOWN
  return QUALITATIVE[label.trim().toUpperCase()] ?? Severity.UNKNOWN
}
