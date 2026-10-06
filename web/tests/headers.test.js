// netlify.toml and security-headers.js must stay identical.

import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { parse } from 'smol-toml'
import { describe, expect, it } from 'vitest'
import { SECURITY_HEADERS } from '../security-headers.js'
import { KEV_PROXY_URL, KEV_URL } from '../src/core/sources/enrich.js'
import { ALLOWED_HOSTS } from '../src/core/sources/http.js'

const netlify = parse(readFileSync(fileURLToPath(new URL('../../netlify.toml', import.meta.url)), 'utf-8'))

describe('deployment config', () => {
  it('Netlify serves exactly the headers tested locally', () => {
    const all = netlify.headers.find((h) => h.for === '/*').values
    expect(all).toEqual(SECURITY_HEADERS)
  })

  it('CSP connect-src allows only what the engine contacts', () => {
    const connect = SECURITY_HEADERS['Content-Security-Policy']
      .split(';')
      .map((d) => d.trim())
      .find((d) => d.startsWith('connect-src'))
    const origins = connect.split(' ').slice(1)
    expect(origins).toEqual(["'self'", 'https://api.osv.dev', 'https://api.first.org'])
    for (const o of origins.slice(1)) expect(ALLOWED_HOSTS.has(new URL(o).hostname)).toBe(true)
  })

  it('KEV proxy rewrite points at the CISA feed', () => {
    const rule = netlify.redirects.find((r) => r.from === KEV_PROXY_URL)
    expect(rule).toMatchObject({ to: KEV_URL, status: 200, force: true })
  })

  it('install scripts are disabled on the build machine', () => {
    expect(netlify.build.environment.NPM_FLAGS).toContain('--ignore-scripts')
  })
})
