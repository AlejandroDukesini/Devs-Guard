// depguard.report/v1 document. Mirrors dep_guard/reporters/json_report.py.
// Field order and values are identical: the shared goldens compare them.

import { recommendedUpgrade } from '../correlate.js'
import { ComponentStatus, PRIORITIES, SEVERITY_ORDER, componentKey, exitCodeFor, priorityRank, purlWithVersion } from '../models.js'


export const SCHEMA = 'depguard.report/v1'

const locations = (c) => c.locations.map((l) => ({ file: l.file, line: l.line }))

export const componentDict = (c) => ({
  name: c.name,
  version: c.version,
  ecosystem: c.ecosystem,
  purl: purlWithVersion(c),
  direct: c.direct,
  scope: c.scope,
  status: c.status,
  unresolved_reason: c.unresolvedReason,
  error: c.error,
  paths: c.paths,
  locations: locations(c),
})

export const findingDict = (f) => ({
  id: f.id,
  aliases: f.aliases,
  summary: f.summary,
  severity: f.severity,
  cvss: { score: f.cvssScore, vector: f.cvssVector },
  cwes: f.cwes,
  package: {
    name: f.component.name,
    version: f.component.version,
    ecosystem: f.component.ecosystem,
    purl: purlWithVersion(f.component),
    direct: f.component.direct,
    scope: f.component.scope,
    paths: f.component.paths,
    locations: locations(f.component),
  },
  fixed_versions: f.fixedVersions,
  references: f.references,
  published: f.published,
  epss: f.epss === null ? null : { score: f.epss, percentile: f.epssPercentile },
  kev: f.kev,
  priority: f.priority,
  reasons: f.reasons.map((r) => ({ code: r.code, text: r.text })),
  status: f.status,
  ignore: f.status === 'ignored' ? { reason: f.ignoreReason, expires: f.ignoreExpires } : null,
})

export function remediation(findings) {
  const byComponent = new Map()
  for (const f of findings) {
    if (f.status !== 'active') continue
    const key = componentKey(f.component)
    if (!byComponent.has(key)) byComponent.set(key, [])
    byComponent.get(key).push(f)
  }
  const out = []
  for (const group of byComponent.values()) {
    const [target, fixes] = recommendedUpgrade(group)
    const comp = group[0].component
    out.push({
      package: comp.name,
      ecosystem: comp.ecosystem,
      current: comp.version,
      upgrade_to: target,
      fixes,
      of: group.length,
      direct: comp.direct,
      via: comp.paths.length ? comp.paths[0] : [],
      top_priority: Math.min(...group.map((f) => priorityRank(f.priority))),
    })
  }
  out.sort((a, b) => a.top_priority - b.top_priority || b.of - a.of || (a.package < b.package ? -1 : a.package > b.package ? 1 : 0))
  for (const r of out) r.top_priority = `P${r.top_priority}`
  return out
}

function summary(components, findings) {
  const active = findings.filter((f) => f.status === 'active')
  const count = (status) => components.filter((c) => c.status === status).length
  return {
    manifests: null, // filled by buildReport
    components: components.length,
    direct: components.filter((c) => c.direct).length,
    vulnerable_components: count(ComponentStatus.VULNERABLE),
    findings: active.length,
    ignored: findings.length - active.length,
    by_priority: Object.fromEntries(PRIORITIES.map((p) => [p, active.filter((f) => f.priority === p).length])),
    by_severity: Object.fromEntries(SEVERITY_ORDER.map((s) => [s, active.filter((f) => f.severity === s).length])),
    unresolved: count(ComponentStatus.UNRESOLVED),
    errors: count(ComponentStatus.ERROR),
    private: count(ComponentStatus.PRIVATE),
  }
}

export function buildReport({ components, findings, manifests, problems, policy, sources, stats, version }) {
  const s = summary(components, findings)
  s.manifests = manifests.length
  return {
    schema: SCHEMA,
    tool: { name: 'depguard', version, runtime: 'browser' },
    generated_at: new Date().toISOString().replace(/\.\d{3}Z$/, '+00:00'),
    verdict: policy.verdict,
    exit_code: exitCodeFor(policy.verdict),
    summary: s,
    policy: {
      violations: policy.violations,
      incomplete_reasons: policy.incompleteReasons,
      expired_ignores: policy.expiredIgnores,
      unused_ignores: policy.unusedIgnores,
    },
    sources,
    manifests,
    findings: findings.map(findingDict),
    remediation: remediation(findings),
    components: components.map(componentDict),
    problems: problems.map((p) => ({ code: p.code, message: p.message, file: p.file })),
    stats,
  }
}
