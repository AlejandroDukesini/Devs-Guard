// depguard.toml parsing with strict validation. Mirrors dep_guard/config.py.
// Dates are handled as ISO strings (YYYY-MM-DD), which order correctly.

import { parse as parseToml } from 'smol-toml'
import { DEFAULT_EPSS_THRESHOLD } from './risk.js'
import { PRIORITIES, SEVERITY_ORDER } from './models.js'

export class ConfigError extends Error {}

export const defaultConfig = () => ({
  exclude: [],
  epss: true,
  kev: true,
  timeout: 20,
  retries: 3,
  cache: true,
  privatePackages: [],
  epssThreshold: DEFAULT_EPSS_THRESHOLD,
  failOnPriority: 'P1',
  failOnSeverity: null,
  failOnKev: true,
  failOnIncomplete: true,
  failOnUnresolved: false,
  failOnExpiredIgnore: true,
  includeDev: true,
  maxIgnoreDays: 365,
  ignores: [],
  source: null,
})

const NUM = 'number'
const SCHEMA = {
  scan: { exclude: ['list', 'exclude'] },
  sources: {
    epss: ['boolean', 'epss'],
    kev: ['boolean', 'kev'],
    timeout: [NUM, 'timeout'],
    retries: ['int', 'retries'],
    cache: ['boolean', 'cache'],
    private_packages: ['list', 'privatePackages'],
  },
  risk: { epss_threshold: [NUM, 'epssThreshold'] },
  policy: {
    fail_on_priority: ['string', 'failOnPriority'],
    fail_on_severity: ['string', 'failOnSeverity'],
    fail_on_kev: ['boolean', 'failOnKev'],
    fail_on_incomplete: ['boolean', 'failOnIncomplete'],
    fail_on_unresolved: ['boolean', 'failOnUnresolved'],
    fail_on_expired_ignore: ['boolean', 'failOnExpiredIgnore'],
    include_dev: ['boolean', 'includeDev'],
    max_ignore_days: ['int', 'maxIgnoreDays'],
  },
}
const IGNORE_KEYS = new Set(['id', 'package', 'reason', 'expires', 'owner'])
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v) && !(v instanceof Date)

function typeOk(kind, v) {
  if (kind === 'list') return Array.isArray(v)
  if (kind === 'int') return Number.isInteger(v) || typeof v === 'bigint'
  return typeof v === kind
}

export function addDays(isoDate, days) {
  const [y, m, d] = isoDate.split('-').map(Number)
  return new Date(Date.UTC(y, m - 1, d + days)).toISOString().slice(0, 10)
}

function toIsoDate(value, where) {
  if (value instanceof Date && !Number.isNaN(value.getTime())) return value.toISOString().slice(0, 10)
  if (typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value)) {
    const back = new Date(`${value}T00:00:00Z`)
    if (!Number.isNaN(back.getTime()) && back.toISOString().slice(0, 10) === value) return value
  }
  throw new ConfigError(`${where}: \`expires\` is required as a date (YYYY-MM-DD)`)
}

export function parseConfigText(text, today, source = 'depguard.toml') {
  let data
  try {
    data = parseToml(text)
  } catch (err) {
    throw new ConfigError(`${source}: invalid TOML: ${String(err.message).split('\n')[0]}`)
  }
  const cfg = parseConfig(data, today)
  cfg.source = source
  return cfg
}

export function parseConfig(data, today) {
  const cfg = defaultConfig()
  for (const [section, value] of Object.entries(data)) {
    if (section === 'ignore') continue
    if (!(section in SCHEMA)) throw new ConfigError(`unknown section [${section}]`)
    if (!isObj(value)) throw new ConfigError(`[${section}] must be a table`)
    for (const [key, raw] of Object.entries(value)) {
      const spec = SCHEMA[section][key]
      if (!spec) throw new ConfigError(`unknown key ${section}.${key}`)
      const [kind, field] = spec
      if (!typeOk(kind, raw)) throw new ConfigError(`${section}.${key} has the wrong type`)
      let v = typeof raw === 'bigint' ? Number(raw) : raw
      if (kind === 'list') {
        if (!v.every((x) => typeof x === 'string')) throw new ConfigError(`${section}.${key} must be a list of strings`)
        v = [...v]
      }
      if (key === 'fail_on_priority') {
        if (v.toLowerCase() === 'none') v = null
        else if (!PRIORITIES.includes(v.toUpperCase()))
          throw new ConfigError(`policy.${key} must be one of: ${PRIORITIES.join(', ')}, none`)
        else v = v.toUpperCase()
      }
      if (key === 'fail_on_severity') {
        if (v.toLowerCase() === 'none') v = null
        else if (!SEVERITY_ORDER.includes(v.toUpperCase()))
          throw new ConfigError(`policy.${key} must be one of: ${SEVERITY_ORDER.join(', ')}, none`)
        else v = v.toUpperCase()
      }
      cfg[field] = v
    }
  }
  if (!(cfg.epssThreshold >= 0 && cfg.epssThreshold <= 1)) throw new ConfigError('risk.epss_threshold must be between 0 and 1')
  if (!(cfg.timeout >= 1 && cfg.timeout <= 300)) throw new ConfigError('sources.timeout must be between 1 and 300 seconds')
  if (!(cfg.retries >= 0 && cfg.retries <= 10)) throw new ConfigError('sources.retries must be between 0 and 10')
  if (!(cfg.maxIgnoreDays >= 1 && cfg.maxIgnoreDays <= 3650))
    throw new ConfigError('policy.max_ignore_days must be between 1 and 3650')
  if (cfg.failOnSeverity === 'UNKNOWN') throw new ConfigError('policy.fail_on_severity cannot be UNKNOWN')
  cfg.ignores = parseIgnores(data.ignore ?? [], cfg.maxIgnoreDays, today)
  return cfg
}

function parseIgnores(raw, maxDays, today) {
  if (!Array.isArray(raw)) throw new ConfigError('[[ignore]] entries must be an array of tables')
  return raw.map((entry, i) => {
    const where = `ignore #${i + 1}`
    if (!isObj(entry)) throw new ConfigError(`${where} must be a table`)
    const unknown = Object.keys(entry).filter((k) => !IGNORE_KEYS.has(k)).sort()
    if (unknown.length) throw new ConfigError(`${where}: unknown key(s) ${unknown.join(', ')}`)
    const id = typeof entry.id === 'string' && entry.id ? entry.id : null
    const pkg = typeof entry.package === 'string' && entry.package ? entry.package : null
    if (!id && !pkg) throw new ConfigError(`${where}: needs \`id\` and/or \`package\``)
    if (typeof entry.reason !== 'string' || entry.reason.trim().length < 10)
      throw new ConfigError(`${where}: \`reason\` is required (at least 10 characters)`)
    const expires = toIsoDate(entry.expires, where)
    if (expires > addDays(today, maxDays)) {
      throw new ConfigError(
        `${where}: expires ${expires} is more than ${maxDays} days ahead ` +
          '(policy.max_ignore_days); permanent ignores are not allowed',
      )
    }
    if (entry.owner !== undefined && typeof entry.owner !== 'string')
      throw new ConfigError(`${where}: \`owner\` must be a string`)
    return { reason: entry.reason.trim(), expires, id, package: pkg, owner: entry.owner ?? null, index: i }
  })
}

export function describeIgnore(rule) {
  const target = [rule.id, rule.package && `package=${rule.package}`].filter(Boolean).join(' ')
  return `ignore #${rule.index + 1} (${target})`
}
