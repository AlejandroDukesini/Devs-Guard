// @vitest-environment jsdom
// The quality suite itself (src/quality): it must run green on this code,
// record failures honestly, and the certificate must never over-claim.
// Set QUALITY_REPORT=path to also write the sealed report (npm run quality).

import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { runQuality, SUITE_SIZE } from '../src/quality/execute.js'
import { SUITE } from '../src/quality/registry.js'
import { RunInProgressError, STATUS, check, runSuite, sanitize, skip } from '../src/quality/runner.js'
import { buildReport, canonicalJson, sha256Hex, summarize, verifyReport } from '../src/quality/report.js'
import { CERT_STATUS, evaluateCertificate } from '../src/quality/certificate.js'
import { HISTORY_KEY, MAX_RUNS, loadHistory, memoryStorage, saveRun } from '../src/quality/history.js'

// Not executable under vitest: they need the served production build or the network.
const EXPECTED_SKIPS = ['DEP-004', 'FUN-006']

describe('quality suite on the current code', () => {
  it('runs every test; nothing fails, only environment-bound tests are skipped', async () => {
    const report = await runQuality({ environment: 'node' })
    if (process.env.QUALITY_REPORT) {
      const out = resolve(process.env.QUALITY_REPORT)
      mkdirSync(dirname(out), { recursive: true })
      writeFileSync(out, JSON.stringify(report, null, 2) + '\n')
    }
    const broken = report.results.filter((r) => r.status === STATUS.FAILED || r.status === STATUS.ERROR)
    expect(broken.map((r) => `${r.id}: ${r.evidence.join(' | ')}`)).toEqual([])
    expect(report.results.filter((r) => r.status === STATUS.SKIPPED).map((r) => r.id).sort()).toEqual(EXPECTED_SKIPS)
    expect(report.summary.total).toBe(SUITE_SIZE)
    expect(report.results.every((r) => r.evidence.length > 0 && r.started_at && r.duration_ms >= 0)).toBe(true)
    expect((await verifyReport(report)).valid).toBe(true)
    // FUN-006 does not apply outside the published build; DEP-004 lacked the network: missing evidence.
    expect(report.results.filter((r) => r.out_of_scope).map((r) => r.id)).toEqual(['FUN-006'])
    const cert = evaluateCertificate(report, report.build)
    expect(cert.status).toBe(CERT_STATUS.INSUFFICIENT)
    expect(cert.reasons.join(' ')).toContain('DEP-004')
  }, 60_000)

  it('covers every category with documented, unique tests', () => {
    expect(new Set(SUITE.map((t) => t.category)).size).toBe(8)
    expect(new Set(SUITE.map((t) => t.id)).size).toBe(SUITE.length)
  })
})

const def = (id, run, extra = {}) => ({
  id,
  name: id,
  description: 'd',
  category: 'unit',
  severity: 'high',
  recommendation: 'r',
  run,
  ...extra,
})

describe('runner records outcomes honestly', () => {
  it('maps assertion failures, skips, exceptions, missing evidence and timeouts', async () => {
    const results = await runSuite([
      def('TST-001', () => 'ok'),
      def('TST-002', () => check(false, 'boom')),
      def('TST-003', () => skip('no network')),
      def('TST-004', () => {
        throw new TypeError('bug')
      }),
      def('TST-005', () => undefined),
      def('TST-006', () => new Promise(() => {}), { timeoutMs: 20 }),
    ])
    expect(results.map((r) => r.status)).toEqual(['passed', 'failed', 'skipped', 'error', 'error', 'error'])
    expect(results[1]).toMatchObject({ evidence: ['boom'], recommendation: 'r' })
    expect(results[0].recommendation).toBeNull()
    expect(results[3].evidence[0]).toBe('TypeError: bug')
    expect(results[4].evidence[0]).toContain('sin aportar evidencia')
    expect(results[5].evidence[0]).toContain('tiempo agotado')
  })

  it('rejects concurrent runs and malformed suites', async () => {
    let release
    const first = runSuite([def('TST-001', () => new Promise((r) => (release = r)).then(() => 'ok'))])
    await new Promise((r) => setTimeout(r, 5))
    await expect(runSuite([def('TST-002', () => 'ok')])).rejects.toThrow(RunInProgressError)
    release()
    await first
    await expect(runSuite([def('bad id', () => 'ok')])).rejects.toThrow('invalid test id')
    await expect(runSuite([def('TST-001', () => 'ok'), def('TST-001', () => 'ok')])).rejects.toThrow('duplicate')
    await expect(runSuite([def('TST-001', () => 'ok', { category: 'vibes' })])).rejects.toThrow('unknown category')
  })

  it('evidence never carries local paths or control characters', () => {
    const text = sanitize('read C:\\Users\\alice\\secret.txt and /home/bob/.ssh/id_rsa' + String.fromCharCode(0x1b))
    expect(text).not.toMatch(/alice|bob/)
    expect(text).not.toContain(String.fromCharCode(0x1b))
    expect(text).toContain('<ruta local>')
  })
})

const result = (id, status, severity = 'high') => ({ id, status, severity, category: 'unit', duration_ms: 1, evidence: ['e'] })
const BUILD = { fingerprint: 'a'.repeat(64), commit: 'abc' }
const sealed = (results, { build = BUILD, suiteSize = results.length } = {}) =>
  buildReport({ runId: 'r1', startedAt: 's', finishedAt: 'f', build, environment: 'test', suiteSize, results })

describe('certificate rules', () => {
  it('no run: not evaluated', () => {
    expect(evaluateCertificate(null, BUILD).status).toBe(CERT_STATUS.NOT_EVALUATED)
  })

  it('all tests executed and passed on this build: approved (internal tests only)', async () => {
    const cert = evaluateCertificate(await sealed([result('A-001', 'passed'), result('A-002', 'passed')]), BUILD)
    expect(cert.status).toBe(CERT_STATUS.APPROVED)
    expect(cert.id).toMatch(/^DG-QC-[0-9A-F]{16}$/)
  })

  it.each([
    ['a critical failure', [result('A-001', 'failed', 'critical')], CERT_STATUS.NOT_APPROVED],
    ['a low-severity failure', [result('A-001', 'failed', 'low')], CERT_STATUS.NOT_APPROVED],
    ['a skipped test', [result('A-001', 'skipped')], CERT_STATUS.INSUFFICIENT],
    ['an execution error', [result('A-001', 'error')], CERT_STATUS.INSUFFICIENT],
  ])('%s is never approved', async (_label, results, status) => {
    const cert = evaluateCertificate(await sealed([result('A-000', 'passed'), ...results]), BUILD)
    expect(cert.status).toBe(status)
  })

  it('failures dominate missing evidence; a partial suite is insufficient', async () => {
    expect(evaluateCertificate(await sealed([result('A-001', 'failed'), result('A-002', 'skipped')]), BUILD).status).toBe(
      CERT_STATUS.NOT_APPROVED,
    )
    expect(evaluateCertificate(await sealed([result('A-001', 'passed')], { suiteSize: 2 }), BUILD).status).toBe(
      CERT_STATUS.INSUFFICIENT,
    )
  })

  it('a test that does not apply to the environment does not block approval, and says so', async () => {
    const outOfScope = { ...result('A-002', 'skipped'), out_of_scope: true }
    const cert = evaluateCertificate(await sealed([result('A-001', 'passed'), outOfScope]), BUILD)
    expect(cert.status).toBe(CERT_STATUS.APPROVED)
    expect(cert.reasons.join(' ')).toContain('No aplica en este entorno: A-002')
  })

  it('runner marks unmet environment requirements as out of scope without running the test', async () => {
    let ran = false
    const [r] = await runSuite([def('TST-001', () => ((ran = true), 'ok'), { requires: ['production'] })], { context: { production: false } })
    expect(ran).toBe(false)
    expect(r).toMatchObject({ status: 'skipped', out_of_scope: true })
  })

  it('reports sealed with the previous schema still verify', async () => {
    const legacy = { ...(await sealed([result('A-001', 'passed')])), schema: 'depguard.quality/v1' }
    const { out_of_scope: _drop, ...summary } = legacy.summary
    const body = { ...legacy, summary }
    delete body.sha256
    const v1 = { ...body, sha256: await sha256Hex(canonicalJson(body)) }
    expect((await verifyReport(v1)).valid).toBe(true)
  })

  it('code changed since the run: outdated; unknown build: insufficient', async () => {
    const report = await sealed([result('A-001', 'passed')])
    const changed = evaluateCertificate(report, { fingerprint: 'b'.repeat(64) })
    expect(changed.status).toBe(CERT_STATUS.OUTDATED)
    expect(changed.stale).toBe(true)
    expect(evaluateCertificate(report, { fingerprint: null }).status).toBe(CERT_STATUS.INSUFFICIENT)
  })
})

describe('report and history', () => {
  it('pass rate counts executed tests only; coverage shows what was skipped', () => {
    const s = summarize([result('A', 'passed'), result('B', 'failed'), result('C', 'skipped'), result('D', 'error')])
    expect(s).toMatchObject({ total: 4, executed: 3, pass_rate: 33.3, coverage: 75 })
    expect(summarize([result('A', 'skipped')]).pass_rate).toBeNull()
  })

  it('canonical JSON ignores key order', () => {
    expect(canonicalJson({ b: 1, a: [{ d: 1, c: 2 }] })).toBe(canonicalJson({ a: [{ c: 2, d: 1 }], b: 1 }))
  })

  it('keeps the latest runs and drops invalid entries', async () => {
    const storage = memoryStorage()
    for (let i = 0; i < MAX_RUNS + 2; i++)
      await saveRun({ ...(await sealed([result('A-001', 'passed')])), run_id: `r${i}`, sha256: undefined }, storage).catch(() => {})
    // Unsealed reports (sha256 removed) never survive a reload.
    expect((await loadHistory(storage)).reports).toHaveLength(0)
    const good = await sealed([result('A-001', 'passed')])
    await saveRun(good, storage)
    expect((await loadHistory(storage)).reports.map((r) => r.run_id)).toEqual(['r1'])
    storage.write(HISTORY_KEY, JSON.stringify({ not: 'a list' }))
    expect(await loadHistory(storage)).toEqual({ reports: [], rejected: 1 })
  })
})
