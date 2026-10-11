// Fake OSV / EPSS / KEV universe served through an injectable fetch, so the
// engine can be exercised end to end without touching the network.
// Shared by the in-browser quality suite and by vitest (tests/helpers.js);
// mirrors tests/osv_mock.py on the Python side.

const json = (status, body, headers = {}) =>
  new Response(typeof body === 'string' ? body : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  })

/**
 * data: { index, epss, kev, vuln(id) -> string | null }
 * Returns { fetchImpl, state }; `state.fail[endpoint]` injects failures
 * (an HTTP status, 'timeout', 'garbage' or a function returning a Response).
 */
export function createMockFetch({ index, epss, kev, vuln }) {
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
      const text = vuln(decodeURIComponent(u.pathname.split('/').pop()))
      return text === null ? json(404, { code: 5, message: 'Bug not found.' }) : json(200, text)
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

// Fixed "today" of the fixtures (ignore expiry dates are relative to it).
export const FIXTURE_TODAY = '2099-01-15'
export const FIXTURE_ORIGIN = 'https://demo.test'

export const mockScanOptions = (mock, extra = {}) => ({
  today: FIXTURE_TODAY,
  fetchImpl: mock.fetchImpl,
  origin: FIXTURE_ORIGIN,
  sleep: async () => {},
  ...extra,
})

const VOLATILE = ['generated_at', 'stats', 'tool']
/** Report without run-dependent fields, as stored in fixtures/golden. */
export const normalise = (report) => Object.fromEntries(Object.entries(report).filter(([k]) => !VOLATILE.includes(k)))
