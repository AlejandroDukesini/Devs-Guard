// Executes the quality suite and records one result per test. A test passes
// only if its body ran to completion; assertion failures, skips and
// unexpected exceptions are recorded as such, never coerced into a pass.

import { clean } from '../core/textutil.js'

export const STATUS = Object.freeze({ PASSED: 'passed', FAILED: 'failed', SKIPPED: 'skipped', ERROR: 'error' })
export const CATEGORIES = ['unit', 'integration', 'functional', 'negative', 'regression', 'performance', 'integrity', 'dependencies']
export const SEVERITIES = ['critical', 'high', 'medium', 'low']

export const DEFAULT_TIMEOUT_MS = 30_000
const MAX_EVIDENCE_LINES = 12
const MAX_EVIDENCE_CHARS = 300
const ID_PATTERN = /^[A-Z]{3,4}-\d{3}$/

// Environment requirements a test may declare (`requires: ['production']`).
// A test whose requirement is not met is not executed: it is recorded as
// skipped with out_of_scope = true, so it is visible but not run.
export const REQUIREMENTS = {
  browser: { label: 'un navegador', met: (ctx) => ctx.env === 'browser' },
  production: { label: 'la build de producción publicada', met: (ctx) => Boolean(ctx.production) },
}

export class AssertionFailure extends Error {}
export class SkipTest extends Error {}
export class RunInProgressError extends Error {}

/** Throws AssertionFailure (status "failed") unless `condition` holds. */
export function check(condition, message) {
  if (!condition) throw new AssertionFailure(message)
}
/** Ends the test as "skipped": it could not be executed in this environment. */
export function skip(reason) {
  throw new SkipTest(reason)
}

// Evidence never carries local filesystem paths, control characters or
// unbounded text.
const LOCAL_PATH = /(?:[A-Za-z]:[\\/]|\/(?:home|Users|root|tmp|var|private)\/)[^\s'"`]*/g
export const sanitize = (text) => clean(String(text).replace(LOCAL_PATH, '<ruta local>'), MAX_EVIDENCE_CHARS)

function normaliseEvidence(value) {
  const lines = (Array.isArray(value) ? value : value === undefined || value === null ? [] : [value]).map(sanitize)
  return lines.length > MAX_EVIDENCE_LINES
    ? [...lines.slice(0, MAX_EVIDENCE_LINES), `… ${lines.length - MAX_EVIDENCE_LINES} línea(s) más`]
    : lines
}

/** Rejects malformed suites before anything runs. */
export function validateSuite(tests) {
  const seen = new Set()
  for (const t of tests) {
    if (!ID_PATTERN.test(t.id ?? '')) throw new Error(`invalid test id: ${t.id}`)
    if (seen.has(t.id)) throw new Error(`duplicate test id: ${t.id}`)
    seen.add(t.id)
    if (!CATEGORIES.includes(t.category)) throw new Error(`${t.id}: unknown category ${t.category}`)
    if (!SEVERITIES.includes(t.severity)) throw new Error(`${t.id}: unknown severity ${t.severity}`)
    for (const r of t.requires ?? []) if (!REQUIREMENTS[r]) throw new Error(`${t.id}: unknown requirement ${r}`)
    if (typeof t.run !== 'function' || !t.name || !t.description || !t.recommendation)
      throw new Error(`${t.id}: incomplete definition`)
  }
}

function withTimeout(promise, ms) {
  let timer
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`tiempo agotado (${ms} ms)`)), ms)
  })
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer))
}

const tick = () => new Promise((resolve) => setTimeout(resolve, 0))
let active = false
export const isRunning = () => active

/**
 * Runs `tests` sequentially. Returns [result]; each result is
 * { id, name, description, category, severity, status, started_at,
 *   duration_ms, evidence[], recommendation|null }.
 * onProgress({ done, total, current }) is called before and after each test.
 */
export async function runSuite(tests, { context = {}, onProgress = () => {}, clock = () => performance.now() } = {}) {
  if (active) throw new RunInProgressError('ya hay una ejecución en curso')
  validateSuite(tests)
  active = true
  try {
    const results = []
    for (const [i, test] of tests.entries()) {
      onProgress({ done: i, total: tests.length, current: test.id })
      await tick() // let the UI paint progress between tests
      const startedAt = new Date().toISOString()
      const t0 = clock()
      let status
      let evidence
      const unmet = (test.requires ?? []).filter((r) => !REQUIREMENTS[r].met(context))
      try {
        if (unmet.length) skip(`No aplica en este entorno: requiere ${unmet.map((r) => REQUIREMENTS[r].label).join(' y ')}.`)
        evidence = await withTimeout(Promise.resolve().then(() => test.run(context)), test.timeoutMs ?? DEFAULT_TIMEOUT_MS)
        // No evidence, no pass.
        if (!normaliseEvidence(evidence).length) throw new Error('la prueba terminó sin aportar evidencia')
        status = STATUS.PASSED
      } catch (err) {
        status = err instanceof AssertionFailure ? STATUS.FAILED : err instanceof SkipTest ? STATUS.SKIPPED : STATUS.ERROR
        evidence = status === STATUS.ERROR ? `${err?.name ?? 'Error'}: ${err?.message ?? err}` : err.message
      }
      const failedOrError = status === STATUS.FAILED || status === STATUS.ERROR
      results.push({
        id: test.id,
        name: test.name,
        description: test.description,
        category: test.category,
        severity: test.severity,
        status,
        started_at: startedAt,
        duration_ms: Math.round((clock() - t0) * 10) / 10,
        evidence: normaliseEvidence(evidence),
        recommendation: failedOrError ? test.recommendation : null,
        out_of_scope: unmet.length > 0,
      })
    }
    onProgress({ done: tests.length, total: tests.length, current: null })
    return results
  } finally {
    active = false
  }
}
