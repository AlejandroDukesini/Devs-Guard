import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { defineConfig, searchForWorkspaceRoot } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { SECURITY_HEADERS } from './security-headers.js'
import { buildInfo } from './build-info.js'

const fromRepo = (path) => fileURLToPath(new URL(`../${path}`, import.meta.url))
const KEV_FEED = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'

// netlify.toml lives outside web/; the quality suite reads it through this
// virtual module instead of widening the dev server's file allow list.
const REPO_FILES_ID = 'virtual:repo-files'
const repoFiles = () => ({
  name: 'repo-files',
  resolveId: (id) => (id === REPO_FILES_ID ? `\0${REPO_FILES_ID}` : null),
  load(id) {
    if (id !== `\0${REPO_FILES_ID}`) return null
    this.addWatchFile(fromRepo('netlify.toml'))
    return `export const netlifyToml = ${JSON.stringify(readFileSync(fromRepo('netlify.toml'), 'utf-8'))}`
  },
})

export default defineConfig({
  plugins: [react(), tailwindcss(), repoFiles()],
  define: { __BUILD_INFO__: JSON.stringify(buildInfo()) },
  server: {
    // The quality suite bundles the shared fixtures (../fixtures) and netlify.toml.
    fs: { allow: [searchForWorkspaceRoot(process.cwd()), fromRepo('fixtures')] },
    // Same contract as the Netlify rewrite in production: /api/kev -> CISA feed.
    proxy: {
      '/api/kev': {
        target: 'https://www.cisa.gov',
        changeOrigin: true,
        rewrite: () => new URL(KEV_FEED).pathname,
      },
    },
  },
  // Production security headers (same as netlify.toml) so e2e runs under the real CSP.
  preview: { headers: SECURITY_HEADERS },
  build: {
    target: 'es2022',
    sourcemap: false,
  },
  test: {
    environment: 'node',
    include: ['tests/**/*.test.{js,jsx}'],
    environmentMatchGlobs: [['tests/**/*.test.jsx', 'jsdom']],
    setupFiles: ['tests/setup.js'],
  },
})
