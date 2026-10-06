// Critical demo flows, fully offline: every non-local request is blocked, so
// these tests also prove that "Instantánea" mode never touches the network.

import { expect, test } from '@playwright/test'

test.beforeEach(async ({ page }) => {
  await page.route(/^https?:\/\/(?!localhost)/, (route) => route.abort())
  await page.goto('/')
})

async function scanSample(page, title) {
  await page.getByRole('radio', { name: 'Instantánea' }).click()
  await page.getByText(title, { exact: true }).click()
  await page.getByRole('button', { name: 'Escanear' }).click()
}

test('landing explains what it is and links to the code', async ({ page }) => {
  await expect(page.getByRole('heading', { level: 1 })).toContainText('Qué vulnerabilidades corregir primero')
  await expect(page.getByRole('link', { name: /Ver código/ })).toHaveAttribute('href', /github\.com\/AlejandroDukesini\/Devs-Guard/)
})

test('Java SBOM: KEV findings become P0 and the policy fails', async ({ page }) => {
  await scanSample(page, 'Servicio Java (SBOM)')
  await expect(page.getByText('Política: FAIL')).toBeVisible()
  await expect(page.getByText('exit 1', { exact: true })).toBeVisible()
  await expect(page.getByText('KEV').first()).toBeVisible()
  // Open a finding flagged KEV: its reasons must say why it is P0.
  await page.locator('li').filter({ hasText: 'KEV' }).first().getByRole('button').first().click()
  await expect(page.getByText(/Por qué es P0/)).toBeVisible()
  await expect(page.getByText('Explotación activa confirmada (CISA KEV)').first()).toBeVisible()
})

test('broken lockfile is INCOMPLETE, never a clean pass', async ({ page }) => {
  await scanSample(page, 'Lockfile con conflicto de merge')
  await expect(page.getByText('Política: INCOMPLETE')).toBeVisible()
  await expect(page.getByText('exit 3', { exact: true })).toBeVisible()
  await expect(page.getByText(/manifest files could not be parsed/)).toBeVisible()
})

test('up-to-date project passes', async ({ page }) => {
  await scanSample(page, 'Servicio al día (pip)')
  await expect(page.getByText('Política: PASS')).toBeVisible()
})

test('own files not covered by the snapshot are reported as not checked', async ({ page }) => {
  await page.getByRole('radio', { name: 'Instantánea' }).click()
  await page.getByRole('radio', { name: 'Tus archivos' }).click()
  await page.getByLabel('Contenido del archivo').fill('some-package==1.2.3\n')
  await page.getByRole('button', { name: 'Escanear' }).click()
  await expect(page.getByText('Política: INCOMPLETE')).toBeVisible()
  await expect(page.getByText('Lo que no se pudo comprobar')).toBeVisible()
})

test('invalid policy is a tool error (exit 2)', async ({ page }) => {
  await page.getByRole('radio', { name: 'Instantánea' }).click()
  await page.getByRole('button', { name: /Política y opciones/ }).click()
  await page.getByLabel(/depguard.toml/).fill('[policy]\nfail_on_kevv = true\n')
  await page.getByRole('button', { name: 'Escanear' }).click()
  await expect(page.getByRole('alert')).toContainText('unknown key policy.fail_on_kevv')
})

test('exports and reset', async ({ page }) => {
  await scanSample(page, 'Tienda Express (npm)')
  await expect(page.getByText('Política: FAIL')).toBeVisible()
  const download = page.waitForEvent('download')
  await page.getByRole('button', { name: 'SARIF' }).click()
  expect((await download).suggestedFilename()).toBe('depguard.sarif')
  await page.getByRole('button', { name: 'Nuevo escaneo' }).click()
  await expect(page.getByText('Elige un ejemplo y pulsa «Escanear»')).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Demo interactiva' })).toBeInViewport()
})
