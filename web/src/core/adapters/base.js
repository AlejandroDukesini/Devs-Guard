// Adapter contract and helpers. Mirrors dep_guard/adapters/base.py.
// An adapter is { id, matches(filename, parentDir), parse(content, ctx) }
// returning { components, problems }. It never executes anything and only
// reads the sibling files offered through ctx.readSibling.

import { Scope } from '../models.js'

export class ParseError extends Error {}

/**
 * BFS over a dependency graph. Production roots are walked first, so a
 * package reachable from both prod and dev is classified as prod. Each node
 * gets the shortest path from a direct dependency.
 */
export function walkGraph(edges, prodRoots, devRoots, label) {
  const direct = new Set([...prodRoots, ...devRoots])
  const info = new Map()
  for (const [roots, scope] of [
    [prodRoots, Scope.PROD],
    [devRoots, Scope.DEV],
  ]) {
    const queue = []
    for (const root of roots) {
      if (!info.has(root)) {
        info.set(root, { direct: true, scope, path: [label(root)] })
        queue.push(root)
      }
    }
    while (queue.length) {
      const node = queue.shift()
      for (const child of edges.get(node) ?? []) {
        if (info.has(child)) continue
        info.set(child, { direct: direct.has(child), scope, path: [...info.get(node).path, label(child)] })
        queue.push(child)
      }
    }
  }
  return info
}

export const location = (ctx, line) => [{ file: ctx.relPath, line }]

export const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v)

/** JSON.parse with the line number of the error, like Python's json module reports. */
export function parseJson(content) {
  try {
    return JSON.parse(content)
  } catch (err) {
    const msg = String(err.message)
    let line
    const lineMatch = /line (\d+)/.exec(msg)
    const posMatch = /position (\d+)/.exec(msg)
    if (lineMatch) line = Number(lineMatch[1])
    else if (posMatch) line = content.slice(0, Number(posMatch[1])).split('\n').length
    else line = content.split('\n').length // unexpected end of input
    throw new ParseError(`invalid JSON at line ${line}`)
  }
}
