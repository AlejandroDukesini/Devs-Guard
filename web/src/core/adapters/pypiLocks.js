// poetry.lock and uv.lock. Mirrors dep_guard/adapters/pypi_locks.py.

import { parse as parseToml } from 'smol-toml'
import { build, normalizePypiName } from '../purl.js'
import { ComponentStatus, Scope, makeComponent } from '../models.js'
import { clean, findLine } from '../textutil.js'
import { parseRequirement } from './requirements.js'
import { ParseError, isObject, location, walkGraph } from './base.js'

function load(content) {
  try {
    return parseToml(content)
  } catch (err) {
    throw new ParseError(`invalid TOML: ${clean(String(err.message), 120)}`)
  }
}

const norm = (name) => (typeof name === 'string' && name ? normalizePypiName(name) : null)

function reqName(spec) {
  if (typeof spec !== 'string') return null
  const req = parseRequirement(spec)
  return req ? normalizePypiName(req.name) : null
}

function component(name, version, ctx, content, info) {
  const comp = makeComponent({
    ecosystem: 'PyPI',
    name,
    version: typeof version === 'string' && version ? version : null,
    purl: build('PyPI', name),
    direct: info ? info.direct : null,
    scope: info ? info.scope : Scope.UNKNOWN,
    locations: location(ctx, findLine(content, `name = "${name}"`)),
    paths: info ? [info.path] : [],
  })
  if (comp.version === null) {
    comp.status = ComponentStatus.UNRESOLVED
    comp.unresolvedReason = 'no version recorded in lockfile'
  }
  return comp
}

const packagesOf = (data) => (Array.isArray(data.package) ? data.package.filter(isObject) : [])

function poetryRoots(pyproject) {
  if (!pyproject) return [[], []]
  let data
  try {
    data = parseToml(pyproject)
  } catch {
    return [[], []]
  }
  const prod = []
  const dev = []
  const push = (arr, values) => values.forEach((v) => v && arr.push(v))
  if (isObject(data.project)) push(prod, (data.project.dependencies ?? []).map(reqName))
  const poetry = isObject(data.tool) && isObject(data.tool.poetry) ? data.tool.poetry : {}
  push(prod, Object.keys(poetry.dependencies ?? {}).filter((k) => k !== 'python').map(norm))
  push(dev, Object.keys(poetry['dev-dependencies'] ?? {}).map(norm))
  if (isObject(poetry.group)) {
    for (const group of Object.values(poetry.group)) {
      if (isObject(group)) push(dev, Object.keys(group.dependencies ?? {}).map(norm))
    }
  }
  if (isObject(data['dependency-groups'])) {
    for (const specs of Object.values(data['dependency-groups'])) {
      if (Array.isArray(specs)) push(dev, specs.map(reqName))
    }
  }
  return [prod, dev]
}

function checkSource(comp, pkg) {
  if (isObject(pkg.source) && ['git', 'directory', 'file', 'url'].includes(pkg.source.type)) {
    comp.version = null
    comp.status = ComponentStatus.UNRESOLVED
    comp.unresolvedReason = 'non-registry source'
  }
  return comp
}

export const poetryLockAdapter = {
  id: 'poetry-lock',
  matches: (filename) => filename === 'poetry.lock',
  parse(content, ctx) {
    const data = load(content)
    const byName = new Map()
    const edges = new Map()
    for (const pkg of packagesOf(data)) {
      const name = norm(pkg.name)
      if (!name) continue
      byName.set(name, pkg)
      edges.set(name, isObject(pkg.dependencies) ? Object.keys(pkg.dependencies).map(norm).filter(Boolean) : [])
    }
    const [prodRoots, devRoots] = poetryRoots(ctx.readSibling('pyproject.toml'))
    const graph = walkGraph(
      edges,
      prodRoots.filter((r) => byName.has(r)),
      devRoots.filter((r) => byName.has(r)),
      (n) => n,
    )
    const hasRoots = prodRoots.length > 0 || devRoots.length > 0
    const result = { components: [], problems: [] }
    for (const [name, pkg] of byName) {
      const info = graph.get(name)
      const comp = component(name, pkg.version, ctx, content, info)
      if (hasRoots && !info) comp.direct = false
      const groups = pkg.groups
      if (Array.isArray(groups) && groups.length) comp.scope = groups.includes('main') ? Scope.PROD : Scope.DEV
      else if (['main', 'dev'].includes(pkg.category)) comp.scope = pkg.category === 'dev' ? Scope.DEV : Scope.PROD
      result.components.push(checkSource(comp, pkg))
    }
    return result
  },
}

const names = (items) =>
  Array.isArray(items) ? items.filter(isObject).map((d) => norm(d.name)).filter(Boolean) : []

export const uvLockAdapter = {
  id: 'uv-lock',
  matches: (filename) => filename === 'uv.lock',
  parse(content, ctx) {
    const data = load(content)
    const byName = new Map()
    const edges = new Map()
    const roots = []
    const prodRoots = []
    const devRoots = []
    for (const pkg of packagesOf(data)) {
      const name = norm(pkg.name)
      if (!name) continue
      byName.set(name, pkg)
      const source = isObject(pkg.source) ? pkg.source : {}
      const isRoot = 'editable' in source || 'virtual' in source
      const prodChildren = names(pkg.dependencies)
      for (const extra of Object.values(pkg['optional-dependencies'] ?? {})) prodChildren.push(...names(extra))
      const devChildren = []
      for (const group of Object.values(pkg['dev-dependencies'] ?? {})) devChildren.push(...names(group))
      edges.set(name, [...prodChildren, ...devChildren])
      if (isRoot) {
        roots.push(name)
        prodRoots.push(...prodChildren)
        devRoots.push(...devChildren)
      }
    }
    const graph = walkGraph(edges, prodRoots, devRoots, (n) => n)
    const result = { components: [], problems: [] }
    for (const [name, pkg] of byName) {
      if (roots.includes(name)) continue
      const comp = component(name, pkg.version, ctx, content, graph.get(name))
      if (roots.length && comp.direct === null) comp.direct = false
      if (isObject(pkg.source) && !('registry' in pkg.source)) {
        comp.version = null
        comp.status = ComponentStatus.UNRESOLVED
        comp.unresolvedReason = 'non-registry source'
      }
      result.components.push(comp)
    }
    return result
  },
}
