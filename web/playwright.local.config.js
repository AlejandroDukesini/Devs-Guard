// E2E of the local app: the real `depguard serve` (Python) with the built UI.
// DEPGUARD_BIN points at the depguard executable (default: on PATH).
import { defineConfig, devices } from '@playwright/test'

export const PORT = 8798
export const TOKEN_FILE = 'test-results/local-session.url'
const bin = process.env.DEPGUARD_BIN ?? 'depguard'

export default defineConfig({
  testDir: 'e2e-local',
  timeout: 60_000,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'github' : 'list',
  use: { baseURL: `http://127.0.0.1:${PORT}`, trace: 'retain-on-failure', reducedMotion: 'reduce' },
  projects: [{ name: 'desktop', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: `"${bin}" serve --port ${PORT} --no-browser --root ../fixtures --token-file ${TOKEN_FILE}`,
    url: `http://127.0.0.1:${PORT}/`,
    // Isolated cache and history: e2e runs never touch the user's real ones.
    env: { DEPGUARD_CACHE_DIR: 'test-results/local-cache' },
    reuseExistingServer: false,
    timeout: 60_000,
  },
})
