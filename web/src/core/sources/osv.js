// OSV.dev client. Mirrors dep_guard/sources/osv.py:
// querybatch (status per exact version, paginated) + /v1/vulns/{id}
// details cached by id@modified.

import { componentKey } from '../models.js'
import { SourceError } from './http.js'

export const BATCH_URL = 'https://api.osv.dev/v1/querybatch'
export const VULN_URL = (id) => `https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`
const BATCH_SIZE = 1000
const MAX_PAGES = 20
const DETAIL_CONCURRENCY = 10
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{1,100}$/

function parseVulns(result) {
  if (result === null || typeof result !== 'object' || Array.isArray(result))
    throw new SourceError('OSV result is not an object')
  const vulns = result.vulns ?? []
  if (!Array.isArray(vulns)) throw new SourceError('OSV vulns is not a list')
  return vulns.map((v) => {
    const id = v?.id
    if (typeof id !== 'string' || !ID.test(id)) throw new SourceError('OSV returned an invalid advisory id')
    return [id, String(v.modified ?? '')]
  })
}

const query = (c, pageToken) => ({
  package: { name: c.name, ecosystem: c.ecosystem },
  version: c.version,
  ...(pageToken ? { page_token: pageToken } : {}),
})

function uniqueSorted(pairs) {
  const seen = new Map(pairs.map((p) => [p.join('\n'), p]))
  return [...seen.values()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0))
}

export class OsvSource {
  constructor(http, cache, offline = false) {
    this.http = http
    this.cache = cache
    this.offline = offline
  }

  async query(components) {
    const outcome = { ids: new Map(), errors: new Map() }
    if (this.offline || !this.http) {
      for (const c of components) {
        const cached = this.cache.get('osv-query', componentKey(c))
        if (Array.isArray(cached)) outcome.ids.set(componentKey(c), cached.map(([i, m]) => [String(i), String(m)]))
        else outcome.errors.set(componentKey(c), 'not available in offline cache')
      }
      return outcome
    }
    for (let start = 0; start < components.length; start += BATCH_SIZE) {
      const chunk = components.slice(start, start + BATCH_SIZE)
      try {
        await this.queryChunk(chunk, outcome)
      } catch (err) {
        if (!(err instanceof SourceError)) throw err
        for (const c of chunk) if (!outcome.errors.has(componentKey(c))) outcome.errors.set(componentKey(c), err.message)
      }
    }
    return outcome
  }

  async queryChunk(chunk, outcome) {
    const data = await this.http.postJson(BATCH_URL, { queries: chunk.map((c) => query(c)) })
    const results = data?.results
    if (!Array.isArray(results) || results.length !== chunk.length)
      throw new SourceError('OSV querybatch returned an unexpected shape')
    for (let i = 0; i < chunk.length; i++) {
      const comp = chunk[i]
      const key = componentKey(comp)
      try {
        const ids = parseVulns(results[i])
        let token = results[i]?.next_page_token
        let pages = 0
        while (token && pages < MAX_PAGES) {
          const page = await this.http.postJson(BATCH_URL, { queries: [query(comp, token)] })
          const pr = page?.results
          if (!Array.isArray(pr) || pr.length !== 1) throw new SourceError('OSV pagination returned an unexpected shape')
          ids.push(...parseVulns(pr[0]))
          token = pr[0]?.next_page_token
          pages++
        }
        if (token) throw new SourceError('too many result pages')
        const unique = uniqueSorted(ids)
        outcome.ids.set(key, unique)
        this.cache.set('osv-query', key, unique)
      } catch (err) {
        if (!(err instanceof SourceError)) throw err
        outcome.errors.set(key, err.message)
      }
    }
  }

  /** {id: modified} -> [records by id, errors by id] */
  async fetch(ids) {
    const records = new Map()
    const errors = new Map()
    const entries = [...ids.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    let next = 0
    const worker = async () => {
      while (next < entries.length) {
        const [vid, modified] = entries[next++]
        const key = `${vid}@${modified}`
        const cached = this.cache.get('osv-vuln', key)
        if (cached && typeof cached === 'object') {
          records.set(vid, cached)
          continue
        }
        if (this.offline || !this.http) {
          errors.set(vid, 'not available in offline cache')
          continue
        }
        try {
          const record = await this.http.getJson(VULN_URL(vid))
          if (record?.id !== vid) {
            errors.set(vid, 'unexpected advisory payload')
            continue
          }
          records.set(vid, record)
          this.cache.set('osv-vuln', key, record)
        } catch (err) {
          if (!(err instanceof SourceError)) throw err
          errors.set(vid, err.message)
        }
      }
    }
    await Promise.all(Array.from({ length: DETAIL_CONCURRENCY }, worker))
    return [records, errors]
  }
}
