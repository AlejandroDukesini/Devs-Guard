// Raw OSV advisories -> findings. Mirrors dep_guard/correlate.py:
// alias grouping, canonical id (CVE > GHSA > first), CVSS v3 severity with
// qualitative fallback, fixed version from the range containing the version.

import { baseScoreV3, severityFromLabel, severityFromScore } from './cvss.js'
import { normalizePypiName } from './purl.js'
import { Severity, severityRank } from './models.js'
import { clean } from './textutil.js'
import { compare } from './versions.js'

const strList = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === 'string') : [])
const byString = (a, b) => (a < b ? -1 : a > b ? 1 : 0)
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v)

export function makeFinding(component, fields) {
  return {
    component,
    id: fields.id,
    aliases: fields.aliases,
    summary: fields.summary,
    severity: fields.severity,
    cvssScore: fields.cvssScore ?? null,
    cvssVector: fields.cvssVector ?? null,
    cwes: fields.cwes ?? [],
    fixedVersions: fields.fixedVersions ?? [],
    references: fields.references ?? [],
    published: fields.published ?? null,
    epss: null,
    epssPercentile: null,
    kev: null,
    priority: 'P3',
    reasons: [],
    status: 'active',
    ignoreReason: null,
    ignoreExpires: null,
  }
}

export const findingCves = (f) => f.aliases.filter((a) => a.startsWith('CVE-'))

export function buildFindings(component, ids, records) {
  const available = ids.filter((i) => records.has(i))
  const missing = ids.filter((i) => !records.has(i))
  const findings = groups(available, records).map((g) => finding(component, g, records))
  for (const vid of missing) {
    findings.push(
      makeFinding(component, {
        id: vid,
        aliases: [vid],
        summary: 'Advisory details unavailable (lookup failed); treat as unreviewed',
        severity: Severity.UNKNOWN,
        references: [`https://osv.dev/vulnerability/${vid}`],
      }),
    )
  }
  return findings.sort((a, b) => byString(a.id, b.id))
}

function groups(ids, records) {
  const parent = new Map()
  const find = (x) => {
    if (!parent.has(x)) parent.set(x, x)
    while (parent.get(x) !== x) {
      parent.set(x, parent.get(parent.get(x)))
      x = parent.get(x)
    }
    return x
  }
  const union = (a, b) => {
    const ra = find(a)
    const rb = find(b)
    if (ra !== rb) {
      const [lo, hi] = ra < rb ? [ra, rb] : [rb, ra]
      parent.set(hi, lo)
    }
  }
  for (const vid of ids) {
    find(vid)
    for (const alias of strList(records.get(vid).aliases)) union(vid, alias)
  }
  const out = new Map()
  for (const vid of ids) {
    const root = find(vid)
    if (!out.has(root)) out.set(root, [])
    out.get(root).push(vid)
  }
  return [...out.values()].map((g) => g.sort(byString))
}

function canonical(allIds) {
  for (const prefix of ['CVE-', 'GHSA-']) {
    const matches = allIds.filter((i) => i.startsWith(prefix)).sort(byString)
    if (matches.length) return matches[0]
  }
  return [...allIds].sort(byString)[0]
}

function finding(component, group, records) {
  const recs = group.map((i) => records.get(i))
  const allIds = [...new Set([...group, ...recs.flatMap((r) => strList(r.aliases))])].sort(byString)
  let bestScore = null
  let bestVector = null
  let label = Severity.UNKNOWN
  const cwes = new Set()
  const published = []
  for (const rec of recs) {
    for (const sev of Array.isArray(rec.severity) ? rec.severity : []) {
      if (isObj(sev) && ['CVSS_V3', 'CVSS_V3_1'].includes(sev.type)) {
        const vector = String(sev.score ?? '')
        const score = baseScoreV3(vector)
        if (score !== null && (bestScore === null || score > bestScore)) {
          bestScore = score
          bestVector = vector
        }
      }
    }
    const db = isObj(rec.database_specific) ? rec.database_specific : {}
    const recLabel = severityFromLabel(db.severity)
    if (severityRank(recLabel) > severityRank(label)) label = recLabel
    for (const c of strList(db.cwe_ids)) if (c.startsWith('CWE-')) cwes.add(c)
    if (typeof rec.published === 'string') published.push(rec.published)
  }
  return makeFinding(component, {
    id: canonical(allIds),
    aliases: allIds,
    summary: summary(recs),
    severity: bestScore !== null ? severityFromScore(bestScore) : label,
    cvssScore: bestScore,
    cvssVector: bestVector ? clean(bestVector, 200) : null,
    cwes: [...cwes].sort(byString),
    fixedVersions: fixedVersions(component, recs),
    references: references(recs),
    published: published.length ? published.sort(byString)[0] : null,
  })
}

function summary(recs) {
  const ordered = [...recs].sort((a, b) => {
    const ga = String(a.id ?? '').startsWith('GHSA-') ? 0 : 1
    const gb = String(b.id ?? '').startsWith('GHSA-') ? 0 : 1
    return ga - gb || byString(a.id ?? '', b.id ?? '')
  })
  for (const rec of ordered) if (typeof rec.summary === 'string' && rec.summary.trim()) return clean(rec.summary, 300)
  for (const rec of ordered) {
    if (typeof rec.details === 'string' && rec.details.trim()) {
      const first = rec.details.trim().split(/\r\n|\r|\n/)[0].replace(/^#+/, '').trim()
      return clean(first, 300)
    }
  }
  return 'No summary provided'
}

function references(recs) {
  const refs = recs.flatMap((r) => (Array.isArray(r.references) ? r.references : [])).filter(isObj)
  // Stable sort: ADVISORY references first, original order otherwise.
  const ordered = refs.filter((r) => r.type === 'ADVISORY').concat(refs.filter((r) => r.type !== 'ADVISORY'))
  const seen = []
  for (const ref of ordered) {
    const url = ref.url
    if (typeof url === 'string' && url.startsWith('https://') && !seen.includes(url)) seen.push(clean(url, 500))
    if (seen.length >= 5) break
  }
  return seen
}

function matchesPackage(component, affected) {
  const pkg = affected.package
  if (!isObj(pkg) || pkg.ecosystem !== component.ecosystem || typeof pkg.name !== 'string') return false
  return component.ecosystem === 'PyPI' ? normalizePypiName(pkg.name) === component.name : pkg.name === component.name
}

function intervals(events) {
  const out = []
  let introduced = null
  for (const ev of Array.isArray(events) ? events : []) {
    if (!isObj(ev)) continue
    if (typeof ev.introduced === 'string') {
      if (introduced !== null) out.push([introduced, null])
      introduced = ev.introduced
    } else if (typeof ev.fixed === 'string' && introduced !== null) {
      out.push([introduced, ev.fixed])
      introduced = null
    } else if (typeof ev.last_affected === 'string' && introduced !== null) {
      out.push([introduced, null])
      introduced = null
    }
  }
  if (introduced !== null) out.push([introduced, null])
  return out
}

const le = (eco, a, b) => {
  const c = compare(eco, a, b)
  return c === null ? null : c <= 0
}
const lt = (eco, a, b) => {
  const c = compare(eco, a, b)
  return c === null ? null : c < 0
}

export function sortVersions(eco, versions) {
  return [...versions].sort((a, b) => compare(eco, a, b) ?? byString(a, b))
}

export function fixedVersions(component, recs) {
  const version = component.version
  if (version === null) return []
  const containing = new Set()
  const everyFix = new Set()
  const eco = component.ecosystem
  for (const rec of recs) {
    for (const affected of Array.isArray(rec.affected) ? rec.affected : []) {
      if (!isObj(affected) || !matchesPackage(component, affected)) continue
      for (const rng of Array.isArray(affected.ranges) ? affected.ranges : []) {
        if (!isObj(rng) || !['ECOSYSTEM', 'SEMVER'].includes(rng.type)) continue
        for (const [introduced, fixed] of intervals(rng.events)) {
          if (fixed === null) continue
          everyFix.add(fixed)
          const lo = introduced === '0' ? true : le(eco, introduced, version)
          const hi = lt(eco, version, fixed)
          if (lo && hi) containing.add(fixed)
        }
      }
    }
  }
  const candidates = containing.size ? containing : new Set([...everyFix].filter((f) => lt(eco, version, f) !== false))
  return sortVersions(eco, candidates)
}

/** Minimum single upgrade that fixes every fixable finding of one component. */
export function recommendedUpgrade(findings) {
  if (!findings.length) return [null, 0]
  const eco = findings[0].component.ecosystem
  const minimal = findings.filter((f) => f.fixedVersions.length).map((f) => f.fixedVersions[0])
  if (!minimal.length) return [null, 0]
  const sorted = sortVersions(eco, new Set(minimal))
  const target = sorted[sorted.length - 1]
  const fixed = findings.filter((f) => f.fixedVersions.length && (compare(eco, f.fixedVersions[0], target) ?? 0) <= 0).length
  return [target, fixed]
}
