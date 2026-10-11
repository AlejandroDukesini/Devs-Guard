// "Centro de seguridad y calidad" and the certificate, on the production
// build under the real CSP, with every non-local request blocked.
// Chain checked: tests run in the page -> results shown -> certificate ->
// downloaded report whose SHA-256 and ids match what the page displays.

import { readFileSync } from 'node:fs'
import { expect, test } from '@playwright/test'
import { buildReport, verifyReport } from '../src/quality/report.js'
import { HISTORY_KEY } from '../src/quality/history.js'

test.setTimeout(120_000)

test.beforeEach(async ({ page }) => {
  await page.route(/^https?:\/\/(?!localhost)/, (route) => route.abort())
  await page.goto('/')
})

const quality = (page) => page.locator('#calidad')
const certificate = (page) => page.locator('#certificado-doc')

test('before any run the certificate says "not evaluated"', async ({ page }) => {
  await expect(quality(page).getByText('Sin ejecuciones todavía.')).toBeVisible()
  await expect(certificate(page).getByTestId('cert-status')).toHaveText('No evaluado')
})

test('a real run in the browser: results, certificate and report agree', async ({ page }) => {
  await quality(page).getByRole('button', { name: 'Ejecutar pruebas de seguridad' }).click()
  await expect(quality(page).getByRole('progressbar')).toBeVisible()
  await expect(quality(page).getByRole('button', { name: 'Ejecutar pruebas de seguridad' })).toBeDisabled()
  await expect(quality(page).getByRole('button', { name: 'Ejecutar pruebas de seguridad' })).toBeEnabled({ timeout: 100_000 })

  // The network is blocked, so the live dependency check (DEP-004) cannot run:
  // it must be "skipped" and the certificate must not claim approval.
  await expect(certificate(page).getByTestId('cert-status')).toHaveText('Evidencia insuficiente')
  await expect(certificate(page)).toContainText('1 prueba(s) omitida(s)')

  // Download the full report and check it against what the page shows.
  const download = page.waitForEvent('download')
  await page.locator('#certificado').getByRole('button', { name: 'Informe' }).click()
  const report = JSON.parse(readFileSync(await (await download).path(), 'utf-8'))
  expect(await verifyReport(report)).toEqual({ valid: true, reason: null })
  expect(report.results.filter((r) => r.status === 'skipped').map((r) => r.id)).toEqual(['DEP-004'])
  expect(report.results.filter((r) => r.status === 'failed' || r.status === 'error')).toEqual([])
  // Served headers were checked for real on this production build.
  expect(report.results.find((r) => r.id === 'FUN-006').status).toBe('passed')
  expect(report.results.find((r) => r.id === 'FUN-005').status).toBe('passed')

  await expect(certificate(page)).toContainText(report.run_id)
  await expect(certificate(page)).toContainText(report.sha256)
  await expect(certificate(page)).toContainText(`DG-QC-${report.sha256.slice(0, 16).toUpperCase()}`)
  await expect(certificate(page)).toContainText(report.build.fingerprint)

  // Every test has a row, and the counters match the report.
  const rows = quality(page).getByRole('region', { name: 'Resultados detallados' }).locator('li')
  await expect(rows).toHaveCount(report.summary.total)
  await expect(quality(page).getByText(`${report.summary.pass_rate} %`).first()).toBeVisible()

  // Filters: only the skipped test remains.
  await quality(page).getByLabel('Estado').selectOption('skipped')
  await expect(rows).toHaveCount(1)
  await expect(rows.first()).toContainText('DEP-004')

  // History survives a reload and is re-verified.
  await page.reload()
  await expect(certificate(page)).toContainText(report.run_id)
})

test('failures are shown and the certificate is not approved', async ({ page }) => {
  const result = (id, status, severity) => ({
    id,
    name: `Prueba ${id}`,
    description: 'd',
    category: 'negative',
    severity,
    status,
    started_at: new Date().toISOString(),
    duration_ms: 1,
    evidence: [status === 'failed' ? 'evidencia del fallo' : 'ok'],
    recommendation: status === 'failed' ? 'Corregir el control roto' : null,
  })
  const failing = await buildReport({
    runId: '00000000-fail-4000-8000-000000000000',
    startedAt: new Date().toISOString(),
    finishedAt: new Date().toISOString(),
    build: { commit: null, dirty: null, fingerprint: null },
    environment: 'browser',
    suiteSize: 2,
    results: [result('NEG-901', 'failed', 'critical'), result('NEG-902', 'passed', 'low')],
  })
  await page.evaluate(([key, value]) => localStorage.setItem(key, value), [HISTORY_KEY, JSON.stringify([failing])])
  await page.reload()
  await expect(certificate(page).getByTestId('cert-status')).toHaveText('No aprobado')
  await expect(certificate(page)).toContainText('1 fallo(s) crítico(s): NEG-901')
  await expect(quality(page).getByText('Corregir el control roto')).toBeVisible()
  await expect(quality(page).getByText('evidencia del fallo')).toBeVisible()

  // A tampered entry is rejected, not displayed.
  const tampered = { ...failing, results: failing.results.map((r) => ({ ...r, status: 'passed' })) }
  await page.evaluate(([key, value]) => localStorage.setItem(key, value), [HISTORY_KEY, JSON.stringify([tampered])])
  await page.reload()
  await expect(quality(page).getByText(/descartada\(s\): su huella no era válida/)).toBeVisible()
  await expect(certificate(page).getByTestId('cert-status')).toHaveText('No evaluado')
})
