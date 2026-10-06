// FIRST EPSS and CISA KEV enrichment. Mirrors dep_guard/sources/enrich.py.
// Unavailable data stays null (unknown); vulnerability status is unaffected.

import { SourceError } from './http.js'

export const EPSS_URL = 'https://api.first.org/data/v1/epss'
// The CISA feed does not send CORS headers, so the browser goes through a
// same-origin proxy (Netlify rewrite in production, Vite proxy in dev).
export const KEV_PROXY_URL = '/api/kev'
export const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
const DAY = 24 * 3600
const EPSS_CHUNK = 100
const CVE = /^CVE-\d{4}-\d{4,7}$/

function epssRow(row) {
  if (!row || typeof row.cve !== 'string') return null
  const epss = Number(row.epss)
  const pct = Number(row.percentile)
  if (!Number.isFinite(epss) || !Number.isFinite(pct) || epss < 0 || epss > 1 || pct < 0 || pct > 1) return null
  return [row.cve, epss, pct]
}

export class EpssSource {
  constructor(http, cache, ttl = DAY) {
    this.http = http
    this.cache = cache
    this.ttl = ttl
  }

  /** -> [Map(cve -> [epss, percentile]), error message | null] */
  async scores(cves) {
    const wanted = [...new Set(cves.filter((c) => CVE.test(c)))].sort()
    const found = new Map()
    const missing = []
    for (const cve of wanted) {
      const cached = this.cache.get('epss', cve, this.ttl)
      if (Array.isArray(cached) && cached.length === 2) found.set(cve, [Number(cached[0]), Number(cached[1])])
      else if (cached === 'none') continue
      else missing.push(cve)
    }
    if (!missing.length) return [found, null]
    if (!this.http) return [found, 'EPSS not available offline for some CVEs']
    try {
      for (let i = 0; i < missing.length; i += EPSS_CHUNK) {
        const chunk = missing.slice(i, i + EPSS_CHUNK)
        const data = await this.http.getJson(EPSS_URL, { cve: chunk.join(','), limit: String(EPSS_CHUNK) })
        if (!Array.isArray(data?.data)) throw new SourceError('EPSS returned an unexpected shape')
        const seen = new Set()
        for (const row of data.data) {
          const parsed = epssRow(row)
          if (!parsed) continue
          const [cve, epss, pct] = parsed
          found.set(cve, [epss, pct])
          seen.add(cve)
          this.cache.set('epss', cve, [epss, pct])
        }
        for (const cve of chunk) if (!seen.has(cve)) this.cache.set('epss', cve, 'none')
      }
    } catch (err) {
      if (!(err instanceof SourceError)) throw err
      return [found, `EPSS unavailable: ${err.message}`]
    }
    return [found, null]
  }
}

export class KevSource {
  constructor(http, cache, { url = KEV_PROXY_URL, ttl = DAY } = {}) {
    this.http = http
    this.cache = cache
    this.url = url
    this.ttl = ttl
  }

  /** -> [Map(cve -> knownRansomwareUse) | null, error | null]; null catalog = unknown */
  async catalog() {
    const toMap = (obj) => new Map(Object.entries(obj).map(([k, v]) => [k, Boolean(v)]))
    const cached = this.cache.get('kev', 'catalog', this.ttl)
    if (cached && typeof cached === 'object') return [toMap(cached), null]
    if (!this.http) {
      const stale = this.cache.get('kev', 'catalog')
      return stale && typeof stale === 'object' ? [toMap(stale), null] : [null, 'CISA KEV not available offline']
    }
    let data
    try {
      data = await this.http.getJson(this.url)
    } catch (err) {
      if (!(err instanceof SourceError)) throw err
      return [null, `CISA KEV unavailable: ${err.message}`]
    }
    if (!Array.isArray(data?.vulnerabilities)) return [null, 'CISA KEV returned an unexpected shape']
    const catalog = {}
    for (const v of data.vulnerabilities) {
      if (v && typeof v.cveID === 'string' && CVE.test(v.cveID))
        catalog[v.cveID] = String(v.knownRansomwareCampaignUse ?? '').toLowerCase() === 'known'
    }
    this.cache.set('kev', 'catalog', catalog)
    return [toMap(catalog), null]
  }
}
