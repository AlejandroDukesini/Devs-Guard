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

test('landing: Neuro Noise hero animates behind the content without errors', async ({ page }) => {
  test.slow() // animates WebGL, which CI renders in software
  const errors = []
  page.on('pageerror', (e) => errors.push(e.message))
  page.on('console', (m) => m.type() === 'error' && errors.push(m.text()))
  await page.reload()
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('DepGuard')
  await expect(page.locator('#top')).toHaveAttribute('data-webgl', /^(on|off)$/)
  await expect(page.getByRole('link', { name: 'Probar la demo' })).toHaveAttribute('href', '#demo')
  await expect(page.getByRole('link', { name: 'Código en GitHub' })).toHaveAttribute('href', /github\.com\/AlejandroDukesini\/Devs-Guard/)

  if ((await page.locator('#top').getAttribute('data-webgl')) === 'on') {
    // Exactly one shader, covering the whole hero.
    const shader = page.locator('#top .hero-shader')
    await expect(shader).toHaveCount(1)
    await expect(shader.locator('canvas')).toHaveCount(1)
    const [hero, bg] = await Promise.all([page.locator('#top').boundingBox(), shader.boundingBox()])
    expect(bg).toEqual(hero)
    // Each sample reads the shader's clock twice, 500 ms apart, in one call.
    const sample = () =>
      shader.evaluate((el) => new Promise((done) => {
        const mount = el.paperShaderMount
        const start = mount.currentFrame
        setTimeout(() => done({ start, end: mount.currentFrame }), 500)
      }))
    // CI renders WebGL in software, so the test lowers the shader's
    // resolution (library API) to keep from starving the parallel tests.
    const mount = await shader.evaluateHandle((el) => el.paperShaderMount)
    await mount.evaluate((m) => m.setMaxPixelCount(160 * 90))
    // The suite emulates reduced motion: still moving, at a quarter speed.
    expect(await mount.evaluate((m) => m.speed)).toBe(0.5)
    const slow = await sample()
    expect(slow.end).toBeGreaterThan(slow.start)
    // With motion allowed it runs at full speed, and keeps going after a resize.
    await page.emulateMedia({ reducedMotion: 'no-preference' })
    expect(await mount.evaluate((m) => m.speed)).toBe(2)
    const moving = await sample()
    const size = page.viewportSize()
    await page.setViewportSize({ width: Math.round(size.width * 0.8), height: size.height })
    const resized = await sample()
    await page.emulateMedia({ reducedMotion: 'reduce' })
    expect(moving.end).toBeGreaterThan(moving.start)
    expect(resized.end).toBeGreaterThan(resized.start)
    expect(resized.start).toBeGreaterThanOrEqual(moving.end)
    // Same instance throughout (no remount), still covering the whole hero.
    expect(await shader.evaluate((el, m) => el.paperShaderMount === m, mount)).toBe(true)
    expect(await shader.boundingBox()).toEqual(await page.locator('#top').boundingBox())
  }

  // The background never takes clicks: the call-to-action links work.
  await page.getByRole('link', { name: 'Ver certificado' }).click()
  await expect(page).toHaveURL(/#certificado$/)
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
  expect(errors).toEqual([])
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
  await expect(page.getByRole('heading', { name: 'Demo', exact: true })).toBeInViewport()
})
