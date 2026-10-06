// Policy evaluation: ignores first, then PASS / FAIL / INCOMPLETE.
// Mirrors dep_guard/policy.py (messages identical).

import { build, normalizePypiName, parse as parsePurl } from './purl.js'
import { ComponentStatus, Scope, Verdict, priorityRank, severityRank } from './models.js'
import { describeIgnore } from './config.js'

export function packageMatches(wanted, comp) {
  if (wanted.startsWith('pkg:')) {
    const parsed = parsePurl(wanted)
    if (!parsed || parsed.ecosystem !== comp.ecosystem) return false
    return build(parsed.ecosystem, parsed.osvName) === comp.purl
  }
  const name = comp.ecosystem === 'PyPI' ? normalizePypiName(wanted) : wanted
  return name === comp.name
}

function matches(rule, finding) {
  if (rule.id && !finding.aliases.some((a) => a.toUpperCase() === rule.id.toUpperCase())) return false
  if (rule.package) return packageMatches(rule.package, finding.component)
  return true
}

export function applyIgnores(findings, rules, today) {
  const result = { verdict: Verdict.PASS, violations: [], incompleteReasons: [], expiredIgnores: [], unusedIgnores: [] }
  const used = new Set()
  const expiredSeen = new Set()
  for (const finding of findings) {
    for (const rule of rules) {
      if (!matches(rule, finding)) continue
      used.add(rule.index)
      if (rule.expires < today) {
        expiredSeen.add(rule.index)
        finding.reasons.push({ code: 'ignore_expired', text: `Excepción caducada el ${rule.expires}` })
        continue
      }
      finding.status = 'ignored'
      finding.ignoreReason = rule.reason
      finding.ignoreExpires = rule.expires
      break
    }
  }
  for (const rule of rules) {
    if (expiredSeen.has(rule.index)) result.expiredIgnores.push(`${describeIgnore(rule)} expired on ${rule.expires}`)
    if (!used.has(rule.index)) result.unusedIgnores.push(`${describeIgnore(rule)} matched no finding`)
  }
  return result
}

export function evaluate(findings, components, config, today, parseFailures = 0) {
  const result = applyIgnores(findings, config.ignores, today)
  for (const f of findings) {
    if (f.status === 'ignored') continue
    if (!config.includeDev && f.component.scope === Scope.DEV) continue
    const label = `${f.id} in ${f.component.name}@${f.component.version}`
    if (config.failOnPriority && priorityRank(f.priority) <= priorityRank(config.failOnPriority))
      result.violations.push(`${label}: priority ${f.priority} (limit ${config.failOnPriority})`)
    else if (config.failOnSeverity && severityRank(f.severity) >= severityRank(config.failOnSeverity))
      result.violations.push(`${label}: severity ${f.severity} (limit ${config.failOnSeverity})`)
    else if (config.failOnKev && f.kev) result.violations.push(`${label}: listed in CISA KEV`)
  }
  if (config.failOnExpiredIgnore) result.violations.push(...result.expiredIgnores)
  const unresolved = components.filter((c) => c.status === ComponentStatus.UNRESOLVED)
  if (config.failOnUnresolved && unresolved.length)
    result.violations.push(`${unresolved.length} dependencies without an exact version`)
  const errors = components.filter((c) => c.status === ComponentStatus.ERROR)
  if (errors.length) result.incompleteReasons.push(`${errors.length} dependencies could not be checked`)
  if (parseFailures) result.incompleteReasons.push(`${parseFailures} manifest files could not be parsed`)

  if (result.violations.length) result.verdict = Verdict.FAIL
  else if (result.incompleteReasons.length && config.failOnIncomplete) result.verdict = Verdict.INCOMPLETE
  return result
}
