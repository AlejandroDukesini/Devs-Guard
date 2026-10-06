// Records real OSV / EPSS / CISA KEV responses for the demo samples, so the
// demo's "Instantánea" mode works without network. It runs the *same* engine
// as the live mode and stores its cache (trimmed to the fields the engine
// reads). Re-run to refresh: `npm run snapshot` (needs internet).

import { readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { scan } from '../src/core/engine.js'
import { Cache } from '../src/core/sources/cache.js'
import { KEV_URL } from '../src/core/sources/enrich.js'

const SAMPLES_DIR = fileURLToPath(new URL('../src/demo/samples/', import.meta.url))
const OUT = fileURLToPath(new URL('../src/demo/snapshot.json', import.meta.url))

const trimRecord = (r) => ({
  id: r.id,
  modified: r.modified,
  published: r.published,
  aliases: r.aliases ?? [],
  summary: r.summary,
  details: typeof r.details === 'string' ? r.details.slice(0, 300) : undefined,
  severity: r.severity,
  database_specific: r.database_specific
    ? { severity: r.database_specific.severity, cwe_ids: r.database_specific.cwe_ids }
    : undefined,
  affected: (r.affected ?? []).map((a) => ({ package: a.package, ranges: a.ranges })),
  references: (r.references ?? []).filter((x) => String(x.url).startsWith('https://')).slice(0, 8),
})

const cache = new Cache()
const verdicts = {}
for (const id of readdirSync(SAMPLES_DIR)) {
  const files = readdirSync(join(SAMPLES_DIR, id)).map((name) => ({
    path: name,
    content: readFileSync(join(SAMPLES_DIR, id, name), 'utf-8'),
  }))
  const report = await scan(files, { cache, kevUrl: KEV_URL, origin: 'https://depguard-demo.invalid' })
  verdicts[id] = { verdict: report.verdict, findings: report.summary.findings, sources: report.sources }
  console.log(id.padEnd(15), report.verdict.padEnd(10), report.summary.by_priority, report.sources)
}

const dump = cache.dump()
const vulns = Object.fromEntries(Object.entries(dump['osv-vuln'] ?? {}).map(([k, r]) => [k, trimRecord(r)]))
const cves = new Set(Object.values(vulns).flatMap((r) => [r.id, ...r.aliases]).filter((a) => a.startsWith('CVE-')))
const kev = Object.fromEntries(Object.entries(dump.kev?.catalog ?? {}).filter(([cve]) => cves.has(cve)))

const snapshot = {
  recorded_at: new Date().toISOString().slice(0, 10),
  note: 'Real responses from api.osv.dev, api.first.org (EPSS) and CISA KEV, trimmed to the fields DepGuard reads.',
  verdicts,
  cache: {
    'osv-query': dump['osv-query'] ?? {},
    'osv-vuln': vulns,
    epss: dump.epss ?? {},
    kev: { catalog: kev },
  },
}
writeFileSync(OUT, JSON.stringify(snapshot) + '\n')
console.log(`wrote ${OUT} (${(JSON.stringify(snapshot).length / 1024).toFixed(0)} KB)`)
