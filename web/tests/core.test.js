// Behaviour of the browser engine beyond the goldens: failures, security, outputs.

import { describe, expect, it } from 'vitest'
import { ToolError, scan } from '../src/core/engine.js'
import { Cache } from '../src/core/sources/cache.js'
import { HttpClient, SourceError } from '../src/core/sources/http.js'
import { DiscoveryError, discover } from '../src/core/discovery.js'
import { clean } from '../src/core/textutil.js'
import { parseConfigText, ConfigError } from '../src/core/config.js'
import { toSarif } from '../src/core/reporters/sarif.js'
import { toCycloneDx } from '../src/core/reporters/cyclonedx.js'
import { parseRequirement } from '../src/core/adapters/requirements.js'
import { TODAY, createMockFetch, projectFiles, scanOptions } from './helpers.js'

describe('"could not determine" is never "no vulnerabilities"', () => {
  it.each([[429], [500], [503], ['timeout'], ['garbage']])('OSV failure %s -> INCOMPLETE', async (how) => {
    const mock = createMockFetch()
    mock.state.fail.batch = how
    const report = await scan(projectFiles('py-uv'), scanOptions(mock))
    const queried = report.components.filter((c) => c.version)
    expect(queried.length).toBeGreaterThan(0)
    expect(queried.every((c) => c.status === 'error')).toBe(true)
    expect(report.verdict).toBe('INCOMPLETE')
    expect(report.exit_code).toBe(3)
    expect(report.sources.osv).toMatch(/^error/)
  })

  it('retries a transient 429', async () => {
    const mock = createMockFetch()
    let first = true
    mock.state.fail.batch = () => {
      if (!first) return null
      first = false
      return new Response('{}', { status: 429, headers: { 'Retry-After': '1' } })
    }
    const report = await scan(projectFiles('py-uv'), scanOptions(mock))
    expect(mock.state.calls.batch).toBe(2)
    expect(report.verdict).toBe('FAIL')
  })

  it('advisory detail failure keeps the finding with UNKNOWN severity', async () => {
    const mock = createMockFetch()
    mock.state.fail.vuln = 503
    const report = await scan(projectFiles('py-uv'), scanOptions(mock))
    expect(report.findings.length).toBeGreaterThan(0)
    expect(report.findings.every((f) => f.severity === 'UNKNOWN')).toBe(true)
    expect(report.findings.filter((f) => f.package.scope === 'prod').every((f) => f.priority !== 'P3')).toBe(true)
  })

  it.each(['epss', 'kev'])('%s outage degrades gracefully', async (endpoint) => {
    const mock = createMockFetch()
    mock.state.fail[endpoint] = 503
    const report = await scan(projectFiles('npm-app'), scanOptions(mock))
    expect(report.sources[endpoint]).toMatch(/^error/)
    expect(report.verdict).toBe('FAIL')
    if (endpoint === 'kev') expect(report.findings.every((f) => f.kev === null)).toBe(true)
  })

  it('offline without cache is INCOMPLETE; a pre-filled cache (snapshot) works with zero requests', async () => {
    const empty = await scan(projectFiles('py-uv'), scanOptions(createMockFetch(), { offline: true }))
    expect(empty.exit_code).toBe(3)

    const cache = new Cache()
    const live = await scan(projectFiles('py-uv'), scanOptions(createMockFetch(), { cache }))
    const recorded = cache.dump()
    const replayCache = new Cache()
    replayCache.load(recorded)
    const mock = createMockFetch()
    const replay = await scan(projectFiles('py-uv'), scanOptions(mock, { cache: replayCache, offline: true }))
    expect(Object.values(mock.state.calls).every((n) => n === 0)).toBe(true)
    expect(replay.findings).toEqual(live.findings)
    expect(replay.sources.osv).toBe('offline-cache')
  })

  it('private packages are never sent to OSV', async () => {
    const mock = createMockFetch()
    const files = [{ path: 'requirements.txt', content: 'acme-crypto==41.0.0\ninternal-billing==1.0\n' }]
    const report = await scan(files, scanOptions(mock, { configText: '[sources]\nprivate_packages = ["internal-*"]\n' }))
    expect(mock.state.bodies.join('')).not.toContain('internal-billing')
    expect(report.components.find((c) => c.name === 'internal-billing').status).toBe('private')
  })
})

describe('security of the engine itself', () => {
  it('refuses non-allowlisted hosts, allows the same-origin KEV proxy', async () => {
    const http = new HttpClient({ fetchImpl: async () => new Response('{}'), origin: 'https://demo.test', sleep: async () => {} })
    for (const url of ['https://evil.example/x', 'http://api.osv.dev/v1/query', 'javascript:alert(1)']) {
      await expect(http.getJson(url)).rejects.toThrow(SourceError)
    }
    await expect(http.getJson('/api/kev')).resolves.toEqual({})
  })

  it('regression: a timeout while reading the body is retried, not an uncaught crash', async () => {
    let calls = 0
    const fetchImpl = async () => {
      calls++
      if (calls === 1) {
        const body = new ReadableStream({
          pull(controller) {
            controller.error(Object.assign(new Error('aborted'), { name: 'AbortError' }))
          },
        })
        return new Response(body, { status: 200 })
      }
      return new Response('{"ok": true}')
    }
    const http = new HttpClient({ fetchImpl, sleep: async () => {} })
    await expect(http.getJson('https://www.cisa.gov/feed.json')).resolves.toEqual({ ok: true })
    expect(calls).toBe(2)
  })

  it('caps response size', async () => {
    const big = 'x'.repeat(5000)
    const http = new HttpClient({ fetchImpl: async () => new Response(big), maxBytes: 1000, sleep: async () => {} })
    await expect(http.getJson('https://api.osv.dev/v1/vulns/X')).rejects.toThrow('size limit')
  })

  it('rejects path traversal and prunes vendored/hidden directories', () => {
    expect(() => discover([{ path: '../etc/passwd', content: '' }])).toThrow(DiscoveryError)
    const { manifests } = discover([
      { path: 'node_modules/x/requirements.txt', content: 'a==1' },
      { path: '.git/requirements.txt', content: 'a==1' },
      { path: 'src/requirements.txt', content: 'a==1' },
    ])
    expect(manifests.map((m) => m.relPath)).toEqual(['src/requirements.txt'])
  })

  it('enforces size limits', () => {
    expect(() => discover([{ path: 'requirements.txt', content: 'x'.repeat(3 * 1024 * 1024) }])).toThrow('larger than')
  })

  it('strips control, bidi and zero-width characters', () => {
    const hostile = 'ok' + String.fromCharCode(0x1b) + '[31mred' + String.fromCharCode(0x07, 0x202e) + 'hid' + String.fromCharCode(0x200b) + 'den'
    expect(clean(hostile)).toBe('ok[31mredhidden')
  })

  it('unsupported single files are a tool error, not an empty pass', async () => {
    await expect(scan([{ path: 'notes.md', content: 'hello' }], scanOptions(createMockFetch()))).rejects.toThrow(ToolError)
  })
})

describe('configuration', () => {
  it.each([
    ['[policy]\nfail_on_kevv = true', 'unknown key'],
    ['[polcy]\n', 'unknown section'],
    ['[policy]\nfail_on_kev = "yes"', 'wrong type'],
    ['[[ignore]]\nid = "CVE-1"\nreason = "long enough reason"\nexpires = 2150-01-01', 'permanent ignores'],
    ['[[ignore]]\nid = "CVE-1"\nreason = "short"\nexpires = 2099-02-01', 'reason'],
    ['[[ignore]]\nreason = "long enough reason"\nexpires = 2099-02-01', 'id'],
  ])('rejects %j', (text, message) => {
    expect(() => parseConfigText(text, TODAY)).toThrow(ConfigError)
    expect(() => parseConfigText(text, TODAY)).toThrow(message)
  })
})

describe('PEP 508 parsing', () => {
  it.each([
    ['requests==2.0', [{ op: '==', version: '2.0' }]],
    ['uvicorn[standard]==0.30.0 ; python_version>"3"', [{ op: '==', version: '0.30.0' }]],
    ['pkg (>=1.0, <2)', [{ op: '>=', version: '1.0' }, { op: '<', version: '2' }]],
  ])('%s', (text, specs) => expect(parseRequirement(text).specs).toEqual(specs))
  it.each(['this is not a requirement !!', 'pkg==', 'pkg[unclosed==1', '==1.0'])('rejects %j', (text) =>
    expect(parseRequirement(text)).toBeNull(),
  )
})

describe('export formats', () => {
  it('SARIF: rules, locations, fingerprints, suppressions', async () => {
    const report = await scan(projectFiles('npm-app'), scanOptions(createMockFetch(), {
      configText: '[[ignore]]\nid = "CVE-2099-1003"\nreason = "documented reason here"\nexpires = 2099-06-30',
    }))
    const run = (await toSarif(report)).runs[0]
    const ruleIds = new Set(run.tool.driver.rules.map((r) => r.id))
    expect(run.results.every((r) => ruleIds.has(r.ruleId))).toBe(true)
    expect(run.results[0].locations[0].physicalLocation.artifactLocation.uri).toBe('package-lock.json')
    const fps = run.results.map((r) => r.partialFingerprints['depguard/v1'])
    expect(new Set(fps).size).toBe(fps.length)
    expect(run.results.filter((r) => r.suppressions).length).toBe(1)
  })

  it('CycloneDX output can be scanned again with the same findings', async () => {
    const report = await scan(projectFiles('npm-app'), scanOptions(createMockFetch()))
    const bom = toCycloneDx(report, 'demo-shop')
    expect(bom.specVersion).toBe('1.6')
    const again = await scan([{ path: 'bom.cdx.json', content: JSON.stringify(bom) }], scanOptions(createMockFetch()))
    const key = (f) => `${f.id}|${f.package.name}|${f.package.version}`
    expect(again.findings.map(key).sort()).toEqual(report.findings.map(key).sort())
  })
})
