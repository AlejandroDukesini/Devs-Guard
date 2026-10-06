// In-memory cache with the same namespaces and semantics as
// dep_guard/sources/cache.py (advisories keyed by id@modified, EPSS/KEV
// with a TTL). The demo's "snapshot" mode is simply this cache pre-filled
// with recorded responses plus the engine's offline mode.

export class Cache {
  constructor({ enabled = true, now = () => Date.now() / 1000 } = {}) {
    this.enabled = enabled
    this.now = now
    this.namespaces = new Map() // namespace -> Map(key -> {storedAt, value})
    this.hits = 0
    this.misses = 0
  }

  ns(namespace) {
    if (!this.namespaces.has(namespace)) this.namespaces.set(namespace, new Map())
    return this.namespaces.get(namespace)
  }

  get(namespace, key, maxAge = null) {
    if (!this.enabled) return null
    const entry = this.namespaces.get(namespace)?.get(key)
    if (!entry || (maxAge !== null && this.now() - entry.storedAt > maxAge)) {
      this.misses++
      return null
    }
    this.hits++
    return structuredClone(entry.value)
  }

  set(namespace, key, value) {
    if (!this.enabled) return
    this.ns(namespace).set(key, { storedAt: this.now(), value: structuredClone(value) })
  }

  /** Serialise for recording snapshots: { namespace: { key: value } }. */
  dump() {
    const out = {}
    for (const [ns, entries] of this.namespaces) {
      out[ns] = Object.fromEntries([...entries].map(([k, v]) => [k, v.value]))
    }
    return out
  }

  load(dumped, storedAt = this.now()) {
    for (const [ns, entries] of Object.entries(dumped)) {
      const target = this.ns(ns)
      for (const [key, value] of Object.entries(entries)) target.set(key, { storedAt, value })
    }
  }
}
