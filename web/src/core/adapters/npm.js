// npm package-lock.json (v2/v3) and package.json. Mirrors dep_guard/adapters/npm.py.

import { build } from '../purl.js'
import { ComponentStatus, Scope, makeComponent, problem } from '../models.js'
import { clean, findLine } from '../textutil.js'
import { isSemver } from '../versions.js'
import { ParseError, isObject, location, parseJson, walkGraph } from './base.js'

export const LOCKFILES = ['package-lock.json', 'npm-shrinkwrap.json']
const DEP_FIELDS = [
  ['dependencies', Scope.PROD],
  ['optionalDependencies', Scope.PROD],
  ['devDependencies', Scope.DEV],
]
const NON_REGISTRY = ['file:', 'link:', 'workspace:', 'git', 'github:', 'gitlab:', 'bitbucket:', 'http']

function loadObject(content) {
  const data = parseJson(content)
  if (!isObject(data)) throw new ParseError('top-level JSON value is not an object')
  return data
}

function exact(spec) {
  let candidate = spec.trim()
  if (candidate.startsWith('=')) candidate = candidate.slice(1)
  if (candidate.startsWith('v')) candidate = candidate.slice(1)
  candidate = candidate.trim()
  return isSemver(candidate) ? candidate : null
}

function unresolvedReason(spec) {
  const s = spec.trim()
  if (NON_REGISTRY.some((p) => s.startsWith(p)) || (s.includes('/') && !s.startsWith('npm:')))
    return 'non-registry source'
  if (['', '*', 'latest', 'x'].includes(s)) return 'no version constraint'
  return `version range (${clean(s, 60)}); commit a package-lock.json`
}

export const packageJsonAdapter = {
  id: 'npm-package-json',
  matches: (filename) => filename === 'package.json',
  parse(content, ctx) {
    const data = loadObject(content)
    const result = {
      components: [],
      problems: [
        problem(
          'no_lockfile',
          'package.json without package-lock.json: only direct dependencies are visible ' +
            'and ranges cannot be resolved',
          ctx.relPath,
        ),
      ],
    }
    for (const [field, scope] of DEP_FIELDS) {
      const section = data[field]
      if (!isObject(section)) continue
      for (const [rawName, rawSpec] of Object.entries(section)) {
        if (typeof rawSpec !== 'string') continue
        let name = rawName
        let spec = rawSpec
        if (spec.startsWith('npm:')) {
          const target = spec.slice(4)
          const at = target.lastIndexOf('@')
          if (at > 0) {
            name = target.slice(0, at)
            spec = target.slice(at + 1)
          }
        }
        const version = exact(spec)
        const comp = makeComponent({
          ecosystem: 'npm',
          name: clean(name, 214),
          version,
          purl: build('npm', name),
          direct: true,
          scope,
          locations: location(ctx, findLine(content, JSON.stringify(rawName))),
          paths: [[clean(name, 214)]],
        })
        if (version === null) {
          comp.status = ComponentStatus.UNRESOLVED
          comp.unresolvedReason = unresolvedReason(spec)
        }
        result.components.push(comp)
      }
    }
    return result
  },
}

function packageName(key, entry) {
  if (typeof entry.name === 'string' && entry.name && key.includes('node_modules/')) return entry.name
  if (key.includes('node_modules/')) return key.slice(key.lastIndexOf('node_modules/') + 'node_modules/'.length)
  return entry.name || key
}

/** Node's module resolution: nearest node_modules walking up the tree. */
function resolve(entries, fromKey, dep) {
  let base = fromKey
  for (;;) {
    const candidate = base ? `${base}/node_modules/${dep}` : `node_modules/${dep}`
    if (entries.has(candidate)) return candidate
    if (!base) return null
    const idx = base.lastIndexOf('/node_modules/')
    base = idx >= 0 ? base.slice(0, idx) : ''
  }
}

export const packageLockAdapter = {
  id: 'npm-package-lock',
  matches: (filename) => LOCKFILES.includes(filename),
  parse(content, ctx) {
    const data = loadObject(content)
    const lockVersion = data.lockfileVersion
    if (![2, 3].includes(lockVersion) || !isObject(data.packages)) {
      throw new ParseError(
        `unsupported lockfileVersion ${clean(String(lockVersion ?? 'None'), 10)}; regenerate it with npm >= 7`,
      )
    }
    const entries = new Map(Object.entries(data.packages).filter(([, v]) => isObject(v)))
    const roots = [...entries.keys()].filter((k) => k === '' || !k.includes('node_modules/'))
    const prodRoots = []
    const devRoots = []
    const edges = new Map()
    for (const [key, entry] of entries) {
      const children = []
      for (const [field, scope] of [...DEP_FIELDS, ['peerDependencies', Scope.PROD]]) {
        const deps = entry[field]
        if (!isObject(deps)) continue
        for (const depName of Object.keys(deps)) {
          const target = resolve(entries, key, depName)
          if (target === null) continue
          children.push(target)
          if (roots.includes(key) && field !== 'peerDependencies')
            (scope === Scope.DEV ? devRoots : prodRoots).push(target)
        }
      }
      edges.set(key, children)
    }
    const graph = walkGraph(edges, prodRoots, devRoots, (key) => packageName(key, entries.get(key)))

    const result = { components: [], problems: [] }
    for (const [key, entry] of entries) {
      if (roots.includes(key) || entry.link === true) continue
      const name = packageName(key, entry)
      const info = graph.get(key)
      // npm flags dev-only packages; absence of the flag means it ships to production.
      const devOnly = entry.dev === true || entry.devOptional === true
      const comp = makeComponent({
        ecosystem: 'npm',
        name: clean(name, 214),
        version: typeof entry.version === 'string' && entry.version ? entry.version : null,
        purl: build('npm', name),
        direct: info ? info.direct : false,
        scope: devOnly ? Scope.DEV : Scope.PROD,
        locations: location(ctx, findLine(content, JSON.stringify(key))),
        paths: info ? [info.path] : [],
      })
      const resolved = entry.resolved
      if (comp.version === null) comp.unresolvedReason = 'no version recorded in lockfile'
      else if (typeof resolved === 'string' && !resolved.startsWith('https://') && !resolved.startsWith('http://')) {
        comp.unresolvedReason = 'non-registry source'
        comp.version = null
      }
      if (comp.version === null) comp.status = ComponentStatus.UNRESOLVED
      result.components.push(comp)
    }
    return result
  },
}
