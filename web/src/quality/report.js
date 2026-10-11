// Quality report (depguard.quality/v1): the results of one run plus the
// identity of the build that was evaluated, sealed with a SHA-256 over its
// canonical JSON. The hash proves the report was not edited after the run;
// it says nothing about how secure the code is.

import { CATEGORIES, STATUS } from './runner.js'

export const REPORT_SCHEMA = 'depguard.quality/v1'
export const PROJECT_NAME = 'DepGuard'

const round1 = (x) => Math.round(x * 10) / 10

/**
 * pass_rate = passed / (passed + failed + error) × 100  (executed tests only)
 * coverage  = (passed + failed + error) / total × 100     (share actually executed)
 * Skipped tests lower the coverage, never raise the pass rate.
 */
export function summarize(results) {
  const count = (status) => results.filter((r) => r.status === status).length
  const passed = count(STATUS.PASSED)
  const failed = count(STATUS.FAILED)
  const skipped = count(STATUS.SKIPPED)
  const error = count(STATUS.ERROR)
  const executed = passed + failed + error
  const total = results.length
  return {
    total,
    passed,
    failed,
    skipped,
    error,
    executed,
    pass_rate: executed ? round1((passed / executed) * 100) : null,
    coverage: total ? round1((executed / total) * 100) : 0,
    critical_failures: results.filter((r) => r.status === STATUS.FAILED && r.severity === 'critical').length,
    tests_duration_ms: round1(results.reduce((sum, r) => sum + r.duration_ms, 0)),
    by_category: Object.fromEntries(
      CATEGORIES.map((c) => {
        const inCat = results.filter((r) => r.category === c)
        return [c, Object.fromEntries(Object.values(STATUS).map((s) => [s, inCat.filter((r) => r.status === s).length]))]
      }),
    ),
  }
}

/** JSON with recursively sorted keys: the byte sequence that is hashed. */
export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`
  if (value && typeof value === 'object')
    return `{${Object.keys(value)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`)
      .join(',')}}`
  return JSON.stringify(value)
}

export async function sha256Hex(text) {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

const withoutSeal = (report) => Object.fromEntries(Object.entries(report).filter(([k]) => k !== 'sha256'))

export async function buildReport({ runId, startedAt, finishedAt, build, environment, suiteSize, results }) {
  const report = {
    schema: REPORT_SCHEMA,
    project: PROJECT_NAME,
    run_id: runId,
    started_at: startedAt,
    finished_at: finishedAt,
    build,
    environment,
    suite_size: suiteSize,
    summary: summarize(results),
    results,
  }
  return { ...report, sha256: await sha256Hex(canonicalJson(report)) }
}

/** -> { valid: boolean, reason: string|null } */
export async function verifyReport(report) {
  if (!report || typeof report !== 'object' || Array.isArray(report)) return { valid: false, reason: 'no es un objeto JSON' }
  if (report.schema !== REPORT_SCHEMA) return { valid: false, reason: `esquema desconocido: ${String(report.schema)}` }
  if (typeof report.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(report.sha256))
    return { valid: false, reason: 'falta la huella SHA-256' }
  if (!Array.isArray(report.results) || typeof report.run_id !== 'string') return { valid: false, reason: 'estructura incompleta' }
  const expected = await sha256Hex(canonicalJson(withoutSeal(report)))
  if (expected !== report.sha256) return { valid: false, reason: 'la huella no coincide: el informe fue modificado' }
  const recomputed = summarize(report.results)
  if (canonicalJson(recomputed) !== canonicalJson(report.summary))
    return { valid: false, reason: 'el resumen no coincide con los resultados' }
  return { valid: true, reason: null }
}
