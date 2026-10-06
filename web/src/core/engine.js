// Scan orchestration in the browser. Mirrors dep_guard/engine.py and
// produces the same depguard.report/v1 document as `depguard scan -f json`.

import { buildFindings, findingCves } from './correlate.js'
import { ConfigError, defaultConfig, parseConfigText } from './config.js'
import { DiscoveryError, discover } from './discovery.js'
import { ParseError } from './adapters/index.js'
import { ComponentStatus, Scope, componentKey, exitCodeFor, priorityRank, problem, severityRank } from './models.js'
import { evaluate } from './policy.js'
import { assess } from './risk.js'
import { buildReport } from './reporters/report.js'
import { Cache } from './sources/cache.js'
import { EpssSource, KEV_PROXY_URL, KevSource } from './sources/enrich.js'
import { HttpClient } from './sources/http.js'
import { OsvSource } from './sources/osv.js'
import { fnmatch } from './discovery.js'

export const ENGINE_VERSION = '1.0.0b1'
export class ToolError extends Error {}

const byStr = (a, b) => (a < b ? -1 : a > b ? 1 : 0)
const todayIso = () => new Date().toISOString().slice(0, 10)

/**
 * files: [{path, content}]
 * options: { today, configText, offline, cache, epss, kev, allowIncomplete,
 *            fetchImpl, kevUrl, sleep, origin, onProgress }
 */
export async function scan(files, options = {}) {
  const started = performance.now()
  const timings = {}
  const today = options.today ?? todayIso()
  const progress = options.onProgress ?? (() => {})

  let config
  try {
    const configName = String(options.configSource ?? 'depguard.toml').split(/[\\/]/).pop()
    config = options.configText?.trim() ? parseConfigText(options.configText, today, configName) : defaultConfig()
  } catch (err) {
    if (err instanceof ConfigError) throw new ToolError(err.message)
    throw err
  }
  Object.assign(config, options.configOverrides ?? {})
  if (options.allowIncomplete) config.failOnIncomplete = false

  let discovered
  try {
    discovered = discover(files, config.exclude)
  } catch (err) {
    if (err instanceof DiscoveryError) throw new ToolError(err.message)
    throw err
  }
  const problems = [...discovered.problems]

  // 1. parse
  let t0 = performance.now()
  const manifests = []
  const parsed = []
  let parseFailures = 0
  for (const mf of discovered.manifests) {
    try {
      const result = mf.adapter.parse(mf.content, { relPath: mf.relPath, readSibling: mf.readSibling })
      manifests.push({ path: mf.relPath, adapter: mf.adapter.id, components: result.components.length, error: null })
      parsed.push(...result.components)
      problems.push(...result.problems)
    } catch (err) {
      if (!(err instanceof ParseError)) throw err
      parseFailures++
      manifests.push({ path: mf.relPath, adapter: mf.adapter.id, components: 0, error: err.message })
      problems.push(problem('parse_error', err.message, mf.relPath))
    }
  }
  const components = mergeComponents(parsed)
  markPrivate(components, config.privatePackages)
  timings.parse_ms = ms(t0)
  progress('parsed', { components: components.length })

  const cache = options.cache ?? new Cache()
  const offline = Boolean(options.offline)
  const http = offline
    ? null
    : new HttpClient({
        fetchImpl: options.fetchImpl,
        retries: config.retries,
        timeout: config.timeout,
        sleep: options.sleep,
        origin: options.origin,
      })
  const sources = {}

  // 2. status + details
  t0 = performance.now()
  const queryable = components.filter(
    (c) => c.version && c.status !== ComponentStatus.PRIVATE && c.status !== ComponentStatus.UNRESOLVED,
  )
  const osv = new OsvSource(http, cache, offline)
  const outcome = await osv.query(queryable)
  const wanted = new Map()
  for (const comp of queryable) {
    const key = componentKey(comp)
    if (outcome.errors.has(key)) {
      comp.status = ComponentStatus.ERROR
      comp.error = outcome.errors.get(key)
      continue
    }
    const ids = outcome.ids.get(key) ?? []
    comp.status = ids.length ? ComponentStatus.VULNERABLE : ComponentStatus.CLEAN
    for (const [vid, modified] of ids) if (!wanted.has(vid) || wanted.get(vid) < modified) wanted.set(vid, modified)
  }
  timings.osv_query_ms = ms(t0)
  progress('queried', { vulnerable: queryable.filter((c) => c.status === ComponentStatus.VULNERABLE).length })

  t0 = performance.now()
  const [records, detailErrors] = await osv.fetch(wanted)
  timings.osv_details_ms = ms(t0)
  if (detailErrors.size) {
    problems.push(
      problem(
        'advisory_details_unavailable',
        `details unavailable for ${detailErrors.size} advisories; shown as UNKNOWN severity`,
        null,
      ),
    )
  }
  const errored = queryable.filter((c) => c.status === ComponentStatus.ERROR)
  if (errored.length) {
    const reasons = [...new Set(errored.map((c) => c.error ?? ''))].sort(byStr).join('; ').slice(0, 300)
    sources.osv = `error: ${errored.length} dependencies not checked (${reasons})`
  } else sources.osv = offline ? 'offline-cache' : 'ok'

  const findings = []
  for (const comp of queryable) {
    if (comp.status === ComponentStatus.VULNERABLE) {
      const ids = outcome.ids.get(componentKey(comp)).map(([vid]) => vid)
      findings.push(...buildFindings(comp, ids, records))
    }
  }

  // 3. enrichment
  t0 = performance.now()
  const useEpss = options.epss ?? config.epss
  const useKev = options.kev ?? config.kev
  const cves = [...new Set(findings.flatMap(findingCves))].sort(byStr)
  if (!useEpss) sources.epss = 'disabled'
  else if (cves.length) {
    const [scores, err] = await new EpssSource(http, cache).scores(cves)
    for (const f of findings) {
      const candidates = findingCves(f).filter((c) => scores.has(c)).map((c) => scores.get(c))
      if (candidates.length) {
        const best = candidates.reduce((a, b) => (b[0] > a[0] || (b[0] === a[0] && b[1] > a[1]) ? b : a))
        f.epss = best[0]
        f.epssPercentile = best[1]
      }
    }
    sources.epss = err ? `error: ${err}` : 'ok'
    if (err) problems.push(problem('epss_unavailable', err, null))
  } else sources.epss = 'not needed'

  if (!useKev) sources.kev = 'disabled'
  else if (findings.length) {
    const [catalog, err] = await new KevSource(http, cache, { url: options.kevUrl ?? KEV_PROXY_URL }).catalog()
    if (catalog) for (const f of findings) f.kev = findingCves(f).some((c) => catalog.has(c))
    sources.kev = err ? `error: ${err}` : 'ok'
    if (err) problems.push(problem('kev_unavailable', err, null))
  } else sources.kev = 'not needed'
  timings.enrich_ms = ms(t0)

  // 4. risk + policy
  t0 = performance.now()
  for (const f of findings) assess(f, { epssThreshold: config.epssThreshold })
  findings.sort(
    (a, b) =>
      priorityRank(a.priority) - priorityRank(b.priority) ||
      severityRank(b.severity) - severityRank(a.severity) ||
      byStr(a.component.name, b.component.name) ||
      byStr(a.component.version ?? '', b.component.version ?? '') ||
      byStr(a.id, b.id),
  )
  components.sort(
    (a, b) => byStr(a.ecosystem, b.ecosystem) || byStr(a.name, b.name) || byStr(a.version ?? '', b.version ?? ''),
  )
  const policy = evaluate(findings, components, config, today, parseFailures)
  for (const msg of policy.unusedIgnores) problems.push(problem('unused_ignore', msg, config.source))
  timings.risk_policy_ms = ms(t0)
  timings.total_ms = ms(started)

  const stats = {
    ...timings,
    http_requests: http ? http.requestCount : 0,
    cache_hits: cache.hits,
    cache_misses: cache.misses,
  }
  return buildReport({ components, findings, manifests, problems, policy, sources, stats, version: ENGINE_VERSION })
}

export function mergeComponents(components) {
  const merged = new Map()
  const rank = { [Scope.PROD]: 0, [Scope.UNKNOWN]: 1, [Scope.DEV]: 2 }
  for (const comp of components) {
    const key = componentKey(comp)
    const existing = merged.get(key)
    if (!existing) {
      merged.set(key, comp)
      continue
    }
    const seenLoc = new Set(existing.locations.map((l) => JSON.stringify(l)))
    for (const l of comp.locations) if (!seenLoc.has(JSON.stringify(l))) existing.locations.push(l)
    const seenPaths = new Set(existing.paths.map((p) => p.join('\n')))
    for (const p of comp.paths) if (!seenPaths.has(p.join('\n'))) existing.paths.push(p)
    existing.paths = existing.paths.slice(0, 3)
    if (existing.direct === true || comp.direct === true) existing.direct = true
    else if (existing.direct === false || comp.direct === false) existing.direct = false
    if (rank[comp.scope] < rank[existing.scope]) existing.scope = comp.scope
    existing.unresolvedReason = existing.unresolvedReason ?? comp.unresolvedReason
  }
  return [...merged.values()]
}

export function markPrivate(components, patterns) {
  if (!patterns.length) return
  for (const comp of components) if (patterns.some((p) => fnmatch(comp.name, p))) comp.status = ComponentStatus.PRIVATE
}

const ms = (start) => Math.round((performance.now() - start) * 10) / 10
export { exitCodeFor }

