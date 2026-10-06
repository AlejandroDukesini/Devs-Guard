// SARIF 2.1.0 from a depguard.report/v1 document. Mirrors dep_guard/reporters/sarif.py.

const INFO_URI = 'https://github.com/AlejandroDukesini/Devs-Guard'
const LEVEL = { P0: 'error', P1: 'error', P2: 'warning', P3: 'note' }
const SEVERITY_SCORE = { CRITICAL: 9.5, HIGH: 8.0, MEDIUM: 5.5, LOW: 2.0, UNKNOWN: 5.0 }

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

const purlNoVersion = (p) => (p.version ? p.purl.slice(0, -(p.version.length + 1)) : p.purl)

function rule(f) {
  const fixed = f.fixed_versions.length
  const help =
    `${f.summary}\n\nAliases: ${f.aliases.join(', ')}\n` +
    (fixed ? `Fixed in: ${f.fixed_versions.join(', ')}\n` : 'No fixed version published.\n') +
    f.references.join('\n')
  return {
    id: f.id,
    name: f.id,
    shortDescription: { text: f.summary.slice(0, 200) },
    fullDescription: { text: f.summary },
    helpUri: `https://osv.dev/vulnerability/${f.id}`,
    help: { text: help },
    defaultConfiguration: { level: LEVEL[f.priority] },
    properties: {
      'security-severity': (f.cvss.score ?? SEVERITY_SCORE[f.severity]).toFixed(1),
      tags: ['security', 'vulnerability', 'dependency', ...f.cwes],
      precision: 'high',
    },
  }
}

async function result(f) {
  const p = f.package
  const loc = p.locations[0]
  const fix = f.fixed_versions.length ? `Upgrade to ${f.fixed_versions[0]}.` : 'No fixed version published.'
  const via = p.direct !== false || !p.paths.length ? '' : ` (transitive via ${p.paths[0].join(' > ')})`
  const out = {
    ruleId: f.id,
    level: LEVEL[f.priority],
    message: { text: `${p.name}@${p.version} is affected by ${f.id} [${f.severity}, ${f.priority}]${via}: ${f.summary} ${fix}` },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: loc ? loc.file : '', uriBaseId: '%SRCROOT%' },
          region: { startLine: loc?.line || 1 },
        },
      },
    ],
    partialFingerprints: { 'depguard/v1': await sha256Hex(`${f.id}|${purlNoVersion(p)}|${p.version}`) },
    properties: { priority: f.priority, package: p.purl, epss: f.epss?.score ?? null, kev: f.kev, reasons: f.reasons.map((r) => r.text) },
  }
  if (f.status === 'ignored')
    out.suppressions = [{ kind: 'external', status: 'accepted', justification: `${f.ignore.reason} (expires ${f.ignore.expires})` }]
  return out
}

export async function toSarif(report) {
  const rules = new Map()
  for (const f of report.findings) if (!rules.has(f.id)) rules.set(f.id, rule(f))
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'DepGuard',
            version: report.tool.version,
            semanticVersion: report.tool.version,
            informationUri: INFO_URI,
            rules: [...rules.keys()].sort().map((k) => rules.get(k)),
          },
        },
        results: await Promise.all(report.findings.map(result)),
        invocations: [
          {
            executionSuccessful: report.verdict !== 'INCOMPLETE',
            toolExecutionNotifications: report.problems.map((p) => ({ level: 'warning', message: { text: `${p.code}: ${p.message}` } })),
          },
        ],
      },
    ],
  }
}
