// Hardened fetch for vulnerability sources. Mirrors dep_guard/sources/http.py:
// HTTPS + host allowlist (plus the same-origin KEV proxy), no redirects,
// size cap, retries with backoff on 429/5xx/network errors, and every
// failure surfaces as SourceError (never as an empty successful answer).

export class SourceError extends Error {}

export const ALLOWED_HOSTS = new Set(['api.osv.dev', 'api.first.org', 'www.cisa.gov'])
const RETRY_STATUS = new Set([429, 500, 502, 503, 504])
const MAX_RETRY_AFTER = 30

const realSleep = (s) => new Promise((resolve) => setTimeout(resolve, s * 1000))

export class HttpClient {
  constructor({
    fetchImpl = globalThis.fetch?.bind(globalThis),
    retries = 3,
    timeout = 20,
    maxBytes = 32 * 1024 * 1024,
    sleep = realSleep,
    origin = globalThis.location?.origin,
  } = {}) {
    this.fetch = fetchImpl
    this.retries = retries
    this.timeout = timeout
    this.maxBytes = maxBytes
    this.sleep = sleep
    this.origin = origin
    this.requestCount = 0
  }

  checkUrl(url) {
    let parsed
    try {
      parsed = new URL(url, this.origin ?? 'https://invalid.invalid')
    } catch {
      throw new SourceError('refusing to contact an invalid URL')
    }
    const sameOrigin = this.origin && parsed.origin === this.origin
    if (!sameOrigin && (parsed.protocol !== 'https:' || !ALLOWED_HOSTS.has(parsed.hostname)))
      throw new SourceError(`refusing to contact non-allowlisted URL host '${parsed.hostname}'`)
    return parsed
  }

  async getJson(url, params) {
    const u = this.checkUrl(url)
    for (const [k, v] of Object.entries(params ?? {})) u.searchParams.set(k, v)
    return this.request('GET', u)
  }

  async postJson(url, body) {
    return this.request('POST', this.checkUrl(url), body)
  }

  async request(method, url, body) {
    let lastError = 'unknown error'
    let retryAfter = null
    for (let attempt = 0; attempt <= this.retries; attempt++) {
      if (attempt) {
        const base = 0.5 * 2 ** (attempt - 1)
        await this.sleep(retryAfter !== null ? Math.min(retryAfter, MAX_RETRY_AFTER) : base + Math.random() * (base / 2))
      }
      this.requestCount++
      const controller = new AbortController()
      // The timeout covers the whole exchange, body included.
      const timer = setTimeout(() => controller.abort(), this.timeout * 1000)
      let text
      try {
        const resp = await this.fetch(url.toString(), {
          method,
          redirect: 'error',
          signal: controller.signal,
          headers: body !== undefined ? { 'Content-Type': 'application/json' } : undefined,
          body: body !== undefined ? JSON.stringify(body) : undefined,
        })
        if (RETRY_STATUS.has(resp.status)) {
          lastError = `HTTP ${resp.status}`
          const ra = Number(resp.headers?.get?.('Retry-After'))
          retryAfter = Number.isFinite(ra) && ra >= 0 ? ra : null
          continue
        }
        if (resp.status !== 200) throw new SourceError(`${url.hostname} answered HTTP ${resp.status}`)
        text = await this.readCapped(resp)
      } catch (err) {
        if (err instanceof SourceError) throw err
        // Aborts and network failures can happen while connecting *or* while
        // reading the body: both are transient and retried, never fatal.
        lastError = err?.name === 'AbortError' ? 'timeout' : `network error (${err?.name ?? 'Error'})`
        retryAfter = null
        continue
      } finally {
        clearTimeout(timer)
      }
      try {
        return JSON.parse(text)
      } catch {
        throw new SourceError(`${url.hostname} returned invalid JSON`)
      }
    }
    throw new SourceError(`${url.hostname} unavailable after ${this.retries + 1} attempts: ${lastError}`)
  }

  async readCapped(resp) {
    if (!resp.body?.getReader) {
      const text = await resp.text()
      if (text.length > this.maxBytes) throw new SourceError('response exceeded size limit')
      return text
    }
    const reader = resp.body.getReader()
    const chunks = []
    let total = 0
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      total += value.byteLength
      if (total > this.maxBytes) {
        await reader.cancel()
        throw new SourceError('response exceeded size limit')
      }
      chunks.push(value)
    }
    const all = new Uint8Array(total)
    let offset = 0
    for (const c of chunks) {
      all.set(c, offset)
      offset += c.byteLength
    }
    return new TextDecoder().decode(all)
  }
}
