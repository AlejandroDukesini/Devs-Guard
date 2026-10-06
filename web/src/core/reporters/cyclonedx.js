// CycloneDX 1.6 (SBOM + vulnerabilities/VEX) from a depguard.report/v1
// document. Mirrors dep_guard/reporters/cyclonedx.py.

const encodeVersion = (v) => encodeURIComponent(v).replace(/%2B/g, '+')
const versionless = (c) => (c.version ? c.purl.slice(0, -(c.version.length + 1)) : c.purl)
export const fullPurl = (c) => (c.version ? `${versionless(c)}@${encodeVersion(c.version)}` : c.purl)

function dependencies(components, rootRef) {
  const byName = new Map()
  for (const c of components) {
    if (!byName.has(c.name)) byName.set(c.name, [])
    byName.get(c.name).push(c)
  }
  const edges = new Map([[rootRef, new Set()]])
  for (const c of components) {
    const ref = fullPurl(c)
    if (!edges.has(ref)) edges.set(ref, new Set())
    if (c.direct) edges.get(rootRef).add(ref)
    for (const path of c.paths) {
      for (let i = 0; i + 1 < path.length; i++) {
        const p = byName.get(path[i]) ?? []
        const ch = byName.get(path[i + 1]) ?? []
        // Only unambiguous edges: never invent a link between versions.
        if (p.length === 1 && ch.length === 1) {
          const pr = fullPurl(p[0])
          if (!edges.has(pr)) edges.set(pr, new Set())
          edges.get(pr).add(fullPurl(ch[0]))
        }
      }
    }
  }
  return [...edges.entries()].sort(([a], [b]) => (a < b ? -1 : 1)).map(([ref, deps]) => ({ ref, dependsOn: [...deps].sort() }))
}

function vulnerability(f) {
  const ref = fullPurl(f.package)
  const v = {
    'bom-ref': `${f.id}|${ref}`,
    id: f.id,
    source: { name: 'OSV', url: `https://osv.dev/vulnerability/${f.id}` },
    references: f.aliases
      .filter((a) => a !== f.id)
      .map((a) => ({ id: a, source: { name: 'OSV', url: `https://osv.dev/vulnerability/${a}` } })),
    ratings: [{ severity: f.severity === 'UNKNOWN' ? 'unknown' : f.severity.toLowerCase() }],
    cwes: f.cwes.map((c) => c.split('-')[1]).filter((n) => /^\d+$/.test(n)).map(Number),
    description: f.summary,
    affects: [{ ref }],
    properties: [
      { name: 'depguard:priority', value: f.priority },
      { name: 'depguard:reasons', value: f.reasons.map((r) => r.text).join(' | ') },
    ],
  }
  if (f.cvss.score !== null) {
    v.ratings = [
      {
        source: { name: 'OSV' },
        score: f.cvss.score,
        severity: f.severity.toLowerCase(),
        method: (f.cvss.vector ?? '').startsWith('CVSS:3.1') ? 'CVSSv31' : 'CVSSv3',
        vector: f.cvss.vector,
      },
    ]
  }
  if (f.fixed_versions.length) v.recommendation = `Upgrade ${f.package.name} to ${f.fixed_versions[0]} or later.`
  if (f.published) v.published = f.published
  if (f.status === 'ignored')
    v.analysis = { state: 'in_triage', detail: `${f.ignore.reason} (exception expires ${f.ignore.expires})` }
  return v
}

export function toCycloneDx(report, rootName = 'project', { withVulnerabilities = true } = {}) {
  const rootRef = 'depguard:root'
  const comps = report.components.filter((c) => c.version)
  const bom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      tools: { components: [{ type: 'application', name: 'depguard', version: report.tool.version }] },
      component: { type: 'application', 'bom-ref': rootRef, name: rootName },
      timestamp: report.generated_at,
    },
    components: comps.map((c) => ({
      type: 'library',
      'bom-ref': fullPurl(c),
      name: c.name,
      purl: fullPurl(c),
      scope: c.scope === 'dev' ? 'excluded' : 'required',
      version: c.version,
    })),
    dependencies: dependencies(comps, rootRef),
  }
  if (withVulnerabilities) bom.vulnerabilities = report.findings.map(vulnerability)
  return bom
}
