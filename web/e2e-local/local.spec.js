// The local app end to end: token hand-off, folder picker, scan, results,
// history and exports, all under the server's real CSP.

import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { expect, test } from '@playwright/test'
import { TOKEN_FILE } from '../playwright.local.config.js'

const sessionUrl = () => new URL(readFileSync(TOKEN_FILE, 'utf-8').trim())

test.beforeEach(async ({ page }) => {
  // Offline e2e: only the local server is reachable.
  await page.route(/^https?:\/\/(?!127\.0\.0\.1)/, (route) => route.abort())
})

test('without the session token the app explains how to open it', async ({ page }) => {
  await page.goto('/')
  await expect(page.getByRole('alert')).toContainText('depguard serve')
})

test('scan a project: picker, results, patch states, history and SPDX export', async ({ page }) => {
  const errors = []
  page.on('pageerror', (e) => errors.push(e.message))
  page.on('console', (m) => m.type() === 'error' && errors.push(m.text()))

  const url = sessionUrl()
  await page.goto(`/${url.hash}`)
  await expect(page.getByRole('heading', { name: 'DepGuard local' })).toBeVisible()
  // The token leaves the address bar immediately.
  await expect(page).toHaveURL(/127\.0\.0\.1:\d+\/$/)

  // Folder picker: root -> ecosystems -> cargo
  await page.getByRole('button', { name: /fixtures/ }).click()
  await page.getByRole('button', { name: /ecosystems/ }).click()
  await page.getByRole('button', { name: /^📁 cargo$/ }).click()
  await expect(page.getByText('Cargo.lock', { exact: true })).toBeVisible()

  // Deterministic offline scan.
  await page.getByLabel(/Última versión publicada/).uncheck()
  await page.getByLabel(/Sin conexión/).check()
  await page.getByRole('button', { name: 'Analizar cargo' }).click()

  await expect(page.getByText('Política: INCOMPLETE')).toBeVisible()
  const deps = page.getByRole('region', { name: 'Dependencias y estado de parches' })
  await expect(deps.getByText('smallvec', { exact: true })).toBeVisible()
  await expect(deps.getByText('versión no identificable').first()).toBeVisible()

  // History keeps the scan; export downloads the server-rendered SPDX.
  await expect(page.getByRole('region', { name: 'Historial de análisis' }).getByText('cargo')).toBeVisible()
  const download = page.waitForEvent('download')
  await page.getByRole('button', { name: 'SPDX' }).click()
  const file = await download
  expect(file.suggestedFilename()).toBe('sbom.spdx.json')
  const body = JSON.parse(readFileSync(await file.path(), 'utf-8'))
  expect(body.spdxVersion).toBe('SPDX-2.3')

  // Delete from history.
  await page.getByRole('button', { name: 'Borrar análisis de cargo' }).click()
  await expect(page.getByRole('button', { name: 'Borrar análisis de cargo' })).toHaveCount(0)

  expect(errors).toEqual([])
})

test('a path outside the allowed folders is refused in the UI', async ({ page }) => {
  await page.goto(`/${sessionUrl().hash}`)
  // An existing absolute folder next to the allowed root (../fixtures): must be refused.
  await page.getByLabel('Ruta de la carpeta del proyecto').fill(resolve('..', 'dep_guard'))
  await page.getByRole('button', { name: 'Ir' }).click()
  await expect(page.getByRole('alert')).toContainText('path is outside the allowed folders')
})

test('ending the session revokes the token and clears it from the tab', async ({ page, request }) => {
  const url = sessionUrl()
  await page.goto(`/${url.hash}`)
  await page.getByRole('button', { name: 'Cerrar sesión' }).click()
  await expect(page.getByRole('alert')).toContainText('Sesión cerrada')
  expect(await page.evaluate(() => sessionStorage.length)).toBe(0)
  const token = url.hash.replace('#token=', '')
  const after = await request.get('/api/info', { headers: { Authorization: `Bearer ${token}` } })
  expect(after.status()).toBe(401)
})
