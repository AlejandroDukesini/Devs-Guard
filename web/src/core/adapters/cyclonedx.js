// CycloneDX JSON SBOM input. Mirrors dep_guard/adapters/cyclonedx.py.

import { build, parse as parsePurl } from '../purl.js'
import { ComponentStatus, Scope, makeComponent, problem } from '../models.js'
import { clean, findLine } from '../textutil.js'
import { ParseError, isObject, location, parseJson, walkGraph } from './base.js'

const MAX_NESTING = 10

function flatten(items, out, depth) {
  if (!Array.isArray(items) || depth > MAX_NESTING) return
  for (const item of items) {
    if (isObject(item)) {
      out.push(item)
      flatten(item.components, out, depth + 1)
    }
  }
}

function label(comp, ref) {
  if (comp) {
    const parsed = parsePurl(comp.purl ?? '')
    if (parsed) return clean(parsed.osvName, 120)
    if (typeof comp.name === 'string') return clean(comp.name, 120)
  }
  return clean(ref, 120)
}

export const cycloneDxAdapter = {
  id: 'cyclonedx-json',
  matches(filename) {
    const lower = filename.toLowerCase()
    return lower.endsWith('.cdx.json') || lower.endsWith('.bom.json') || ['bom.json', 'sbom.json'].includes(lower)
  },
  parse(content, ctx) {
    const data = parseJson(content)
    if (!isObject(data) || data.bomFormat !== 'CycloneDX')
      throw new ParseError('not a CycloneDX JSON document (bomFormat != CycloneDX)')

    const result = { components: [], problems: [] }
    const flat = []
    flatten(data.components, flat, 0)
    const nodes = new Map()
    for (const comp of flat) {
      const ref = comp['bom-ref'] || comp.purl
      if (typeof ref === 'string') nodes.set(ref, comp)
    }
    const edges = new Map()
    for (const dep of Array.isArray(data.dependencies) ? data.dependencies : []) {
      if (isObject(dep) && typeof dep.ref === 'string')
        edges.set(dep.ref, (Array.isArray(dep.dependsOn) ? dep.dependsOn : []).filter((d) => typeof d === 'string'))
    }
    const rootComp = isObject(data.metadata) ? data.metadata.component : null
    const rootRef = isObject(rootComp) ? rootComp['bom-ref'] : null
    const hasGraph = edges.size > 0 && typeof rootRef === 'string' && edges.has(rootRef)
    const graph = hasGraph ? walkGraph(edges, edges.get(rootRef), [], (r) => label(nodes.get(r), r)) : new Map()

    const skipped = new Set()
    for (const [ref, comp] of nodes) {
      const parsed = parsePurl(comp.purl ?? '')
      if (!parsed) {
        result.problems.push(problem('missing_purl', `component ${clean(ref, 80)} has no valid purl`, ctx.relPath))
        continue
      }
      if (!parsed.ecosystem) {
        skipped.add(parsed.type)
        continue
      }
      const info = graph.get(ref)
      const component = makeComponent({
        ecosystem: parsed.ecosystem,
        name: clean(parsed.osvName, 300),
        version: parsed.version,
        purl: build(parsed.ecosystem, parsed.osvName),
        direct: info ? info.direct : hasGraph ? false : null,
        scope: comp.scope === 'excluded' ? Scope.DEV : Scope.PROD,
        locations: location(ctx, findLine(content, JSON.stringify(comp.purl))),
        paths: info ? [info.path] : [],
      })
      if (component.version === null) {
        component.status = ComponentStatus.UNRESOLVED
        component.unresolvedReason = 'purl has no version'
      }
      result.components.push(component)
    }
    if (skipped.size) {
      result.problems.push(
        problem(
          'unsupported_purl_types',
          'components skipped, purl types not supported: ' + [...skipped].sort().join(', '),
          ctx.relPath,
        ),
      )
    }
    return result
  },
}
