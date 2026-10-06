// Shared vocabulary of the engine. Mirrors dep_guard/models.py.
// Plain objects are used for components and findings; these constants keep
// the string values identical to the Python implementation (and the JSON
// report schema depguard.report/v1).

export const Scope = Object.freeze({ PROD: 'prod', DEV: 'dev', UNKNOWN: 'unknown' })

export const ComponentStatus = Object.freeze({
  CLEAN: 'clean', // queried successfully, no known advisories
  VULNERABLE: 'vulnerable', // queried successfully, advisories found
  UNRESOLVED: 'unresolved', // no exact version -> not queried
  PRIVATE: 'private', // matched private_packages -> deliberately not sent
  ERROR: 'error', // query failed -> status unknown
})

export const Severity = Object.freeze({
  CRITICAL: 'CRITICAL',
  HIGH: 'HIGH',
  MEDIUM: 'MEDIUM',
  LOW: 'LOW',
  UNKNOWN: 'UNKNOWN',
})
export const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
const SEVERITY_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 }
export const severityRank = (s) => SEVERITY_RANK[s]

export const PRIORITIES = ['P0', 'P1', 'P2', 'P3']
export const priorityRank = (p) => Number(p[1])

export const FindingStatus = Object.freeze({ ACTIVE: 'active', IGNORED: 'ignored' })

export const Verdict = Object.freeze({ PASS: 'PASS', FAIL: 'FAIL', INCOMPLETE: 'INCOMPLETE' })

export function makeComponent(fields) {
  return {
    ecosystem: fields.ecosystem,
    name: fields.name,
    version: fields.version ?? null,
    purl: fields.purl,
    direct: fields.direct ?? null,
    scope: fields.scope ?? Scope.UNKNOWN,
    locations: fields.locations ?? [],
    paths: fields.paths ?? [],
    unresolvedReason: fields.unresolvedReason ?? null,
    status: fields.status ?? ComponentStatus.CLEAN,
    error: fields.error ?? null,
  }
}

export const componentKey = (c) => `${c.purl}@${c.version ?? ''}`
export const purlWithVersion = (c) => (c.version ? `${c.purl}@${c.version}` : c.purl)

export const problem = (code, message, file = null) => ({ code, message, file })

/** Python's repr() of a float: 10.0 stays "10.0", 7.5 stays "7.5". */
export function pyFloat(x) {
  return Number.isInteger(x) ? x.toFixed(1) : String(x)
}

/** Lexicographic comparison of arrays of numbers/strings (Python tuple order). */
export function compareTuples(a, b) {
  const n = Math.min(a.length, b.length)
  for (let i = 0; i < n; i++) {
    if (a[i] < b[i]) return -1
    if (a[i] > b[i]) return 1
  }
  return a.length - b.length < 0 ? -1 : a.length - b.length > 0 ? 1 : 0
}

/**
 * Python's f"{x:.{d}f}": correctly rounded, ties to even. JS toFixed rounds
 * exact ties up, so a tie is detected on the long exact expansion first.
 */
export function pyFixed(x, d) {
  const long = x.toFixed(Math.min(100, d + 30))
  const [intPart, frac = ''] = long.split('.')
  const kept = frac.slice(0, d)
  const rest = frac.slice(d)
  if (/^50*$/.test(rest)) {
    const lastDigit = Number((intPart + kept).slice(-1))
    if (lastDigit % 2 === 0) return d ? `${intPart}.${kept}` : intPart
  }
  return x.toFixed(d)
}

/** Exit code the CLI would return for a verdict (0 pass, 1 fail, 3 incomplete). */
export const exitCodeFor = (verdict) => (verdict === Verdict.FAIL ? 1 : verdict === Verdict.INCOMPLETE ? 3 : 0)
