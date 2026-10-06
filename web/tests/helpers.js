// Test helpers: load the shared fixtures (../fixtures) and serve the fake
// OSV/EPSS/KEV universe through an injectable fetch, like tests/osv_mock.py.

import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

export const FIXTURES = fileURLToPath(new URL('../../fixtures/', import.meta.url))
export const TODAY = '2099-01-15'
export const readJson = (rel) => JSON.parse(readFileSync(join(FIXTURES, rel), 'utf-8'))
export const readText = (rel) => readFileSync(join(FIXTURES, rel), 'utf-8')

/** All files of a fixture project as [{path, content}] (relative POSIX paths). */
export function projectFiles(project) {
  const root = join(FIXTURES, 'projects', project)
  const out = []
  const walk = (dir) => {
    for (const name of readdirSync(dir)) {
      const full = join(dir, name)
      if (statSync(full).isDirectory()) walk(full)
      else out.push({ path: relative(root, full).split(sep).join('/'), content: readFileSync(full, 'utf-8') })
    }
  }
  walk(root)
  return out
}

const json = (status, body, headers = {}) =>
  new Response(typeof body === 'string' ? body : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  })

/** Fake fetch backed by fixtures/osv-mock. `state.fail[endpoint]` injects failures. */
export function createMockFetch() {
  const index = readJson('osv-mock/index.json')
  const epss = readJson('osv-mock/epss.json')
  const kev = readJson('osv-mock/kev.json')
  const state = { fail: {}, calls: { batch: 0, vuln: 0, epss: 0, kev: 0 }, bodies: [] }

  const failure = (endpoint) => {
    const how = state.fail[endpoint]
    if (how === undefined) return null
    if (how === 'timeout') throw Object.assign(new Error('aborted'), { name: 'AbortError' })
    if (how === 'garbage') return json(200, '<html>not json</html>')
    if (typeof how === 'function') return how()
    return json(how, {})
  }

  const fetchImpl = async (url, init = {}) => {
    const u = new URL(url)
    if (u.hostname === 'api.osv.dev' && u.pathname === '/v1/querybatch') {
      state.calls.batch++
      state.bodies.push(init.body)
      const f = failure('batch')
      if (f) return f
      const { queries } = JSON.parse(init.body)
      const results = queries.map((q) => {
        const ids = index.results[`${q.package.ecosystem}|${q.package.name}|${q.version}`] ?? []
        return ids.length ? { vulns: ids.map((id) => ({ id, modified: index.modified })) } : {}
      })
      return json(200, { results })
    }
    if (u.hostname === 'api.osv.dev' && u.pathname.startsWith('/v1/vulns/')) {
      state.calls.vuln++
      const f = failure('vuln')
      if (f) return f
      const id = decodeURIComponent(u.pathname.split('/').pop())
      try {
        return json(200, readText(`osv-mock/vulns/${id}.json`))
      } catch {
        return json(404, { code: 5, message: 'Bug not found.' })
      }
    }
    if (u.hostname === 'api.first.org') {
      state.calls.epss++
      const f = failure('epss')
      if (f) return f
      const cves = (u.searchParams.get('cve') ?? '').split(',')
      const data = cves
        .filter((c) => c in epss)
        .map((c) => ({ cve: c, epss: epss[c][0].toFixed(9), percentile: epss[c][1].toFixed(9), date: '2099-01-01' }))
      return json(200, { status: 'OK', data })
    }
    if (u.pathname === '/api/kev') {
      state.calls.kev++
      const f = failure('kev')
      if (f) return f
      return json(200, kev)
    }
    throw new Error(`unexpected request ${url}`)
  }
  return { fetchImpl, state }
}

export const scanOptions = (mock, extra = {}) => ({
  today: TODAY,
  fetchImpl: mock.fetchImpl,
  origin: 'https://demo.test',
  sleep: async () => {},
  ...extra,
})

const VOLATILE = ['generated_at', 'stats', 'tool']
export const normalise = (report) => Object.fromEntries(Object.entries(report).filter(([k]) => !VOLATILE.includes(k)))
