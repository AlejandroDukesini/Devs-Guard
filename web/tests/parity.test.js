// Parity with the Python reference engine: same inputs, same outputs.
// Inputs and expected results live in ../fixtures and are shared with pytest.

import { describe, expect, it } from 'vitest'
import { compare } from '../src/core/versions.js'
import { baseScoreV3 } from '../src/core/cvss.js'
import { assess } from '../src/core/risk.js'
import { makeFinding } from '../src/core/correlate.js'
import { makeComponent } from '../src/core/models.js'
import { scan } from '../src/core/engine.js'
import { createMockFetch, normalise, projectFiles, readJson, readText, scanOptions } from './helpers.js'

describe('golden algorithm tables', () => {
  it.each(readJson('golden/versions.json').cases)('compare(%s, %s, %s) = %s', (eco, a, b, expected) => {
    expect(compare(eco, a, b)).toBe(expected)
    if (expected !== null) expect(compare(eco, b, a)).toBe(-expected || 0)
  })

  it.each(readJson('golden/cvss.json').cases)('CVSS %s = %s', (vector, score) => {
    expect(baseScoreV3(vector)).toBe(score)
  })

  const riskCases = readJson('golden/risk.json').cases
  it.each(riskCases.map((c) => [c.name, c]))('risk: %s', (_name, c) => {
    const i = c.in
    const component = makeComponent({
      ecosystem: 'npm',
      name: 'pkg',
      version: '1.0.0',
      purl: 'pkg:npm/pkg',
      direct: i.direct,
      scope: i.scope,
      paths: i.path ? [i.path] : [],
    })
    const finding = makeFinding(component, {
      id: 'X',
      aliases: i.cves ? ['CVE-2099-0001'] : ['GHSA-x'],
      summary: 's',
      severity: i.severity,
      cvssScore: i.cvss,
      fixedVersions: i.fix ? [i.fix] : [],
    })
    finding.epss = i.epss
    finding.epssPercentile = i.epss !== null ? 0.5 : null
    finding.kev = i.kev
    assess(finding)
    expect(finding.priority).toBe(c.priority)
    expect(finding.reasons.map((r) => r.code)).toEqual(c.reasons)
  })
})

// Same cases as tests/regen_golden.py::CASES
const CASES = [
  ['npm-app', 'npm-app', null],
  ['npm-app-policy', 'npm-app', 'configs/npm-app-policy.toml'],
  ['npm-no-lock', 'npm-no-lock', null],
  ['py-uv', 'py-uv', null],
  ['py-poetry', 'py-poetry', null],
  ['py-requirements', 'py-requirements', null],
  ['sbom', 'sbom', null],
  ['malformed', 'malformed', null],
]

describe('end-to-end reports match the Python goldens', () => {
  it.each(CASES)('%s', async (name, project, config) => {
    const mock = createMockFetch()
    const configText = config ? readText(config) : undefined
    const report = await scan(projectFiles(project), scanOptions(mock, { configText, configSource: config }))
    const expected = readJson(`golden/report-${name}.json`)
    expect(normalise(report)).toEqual(expected)
  })
})
