// One quality run: execute the suite, then seal the results with the build
// identity. Entry point for both the web ("Ejecutar pruebas de seguridad")
// and vitest. Loaded on demand so the demo does not ship the suite upfront.

import { SUITE } from './registry.js'
import { runSuite } from './runner.js'
import { buildReport } from './report.js'
import { BUILD } from './buildInfo.js'

/**
 * environment: 'browser' | 'node'. network: may DEP-004 query OSV.dev?
 * production: is this the production build (served headers are checkable)?
 */
export async function runQuality({ environment, network = false, production = false, origin = null, onProgress } = {}) {
  const startedAt = new Date().toISOString()
  const results = await runSuite(SUITE, { context: { env: environment, network, production, origin }, onProgress })
  return buildReport({
    runId: globalThis.crypto.randomUUID(),
    startedAt,
    finishedAt: new Date().toISOString(),
    build: BUILD,
    environment: `${environment}${production ? ' (producción)' : ''}`,
    suiteSize: SUITE.length,
    results,
  })
}

export const SUITE_SIZE = SUITE.length
