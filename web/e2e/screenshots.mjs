// Manual visual check: `node e2e/screenshots.mjs` with `vite preview` running on :4173.
// Writes PNGs to test-results/screens (git-ignored).

import { chromium, devices } from '@playwright/test'
import { mkdirSync } from 'node:fs'

const OUT = 'test-results/screens'
mkdirSync(OUT, { recursive: true })
const browser = await chromium.launch()

for (const [name, opts] of [
  ['desktop', { viewport: { width: 1366, height: 900 } }],
  ['mobile', devices['Pixel 7']],
]) {
  for (const scheme of ['light', 'dark']) {
    const page = await browser.newPage({ ...opts, colorScheme: scheme })
    await page.route(/^https?:\/\/(?!localhost)/, (r) => r.abort())
    await page.goto('http://localhost:4173/')
    await page.screenshot({ path: `${OUT}/${name}-${scheme}-landing.png` })
    await page.getByRole('radio', { name: 'Instantánea' }).click()
    await page.getByText('Servicio Java (SBOM)', { exact: true }).click()
    await page.getByRole('button', { name: 'Escanear' }).click()
    await page.getByText('Política: FAIL').waitFor()
    await page.locator('li').filter({ hasText: 'KEV' }).first().getByRole('button').first().click()
    await page.locator('#demo').screenshot({ path: `${OUT}/${name}-${scheme}-demo.png` })
    await page.close()
  }
}
await browser.close()
console.log('screenshots in', OUT)
