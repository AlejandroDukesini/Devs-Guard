import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { SECURITY_HEADERS } from './security-headers.js'

const KEV_FEED = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
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
