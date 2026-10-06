// In-browser equivalent of dep_guard/discovery.py. The input is a list of
// {path, content} (paths relative, POSIX); nothing touches a filesystem.
// Same rules: vendored/hidden directories pruned, a lockfile supersedes the
// package.json next to it, size/count limits, and only pyproject.toml can be
// read as a sibling. Order matches Python's os.walk with sorted entries.

import { SUPERSEDED_BY, adapterFor, sniffAdapter } from './adapters/index.js'
import { problem } from './models.js'

export const MAX_FILE_BYTES = 2 * 1024 * 1024 // tighter than the CLI: this runs in a browser tab
export const MAX_TOTAL_BYTES = 8 * 1024 * 1024
export const MAX_FILES = 200
const MAX_DEPTH = 12
const SKIP_DIRS = new Set(['node_modules', 'bower_components', 'venv', 'env', 'site-packages', '__pycache__', 'dist', 'build', 'target', 'vendor'])
const SIBLING_ALLOWLIST = new Set(['pyproject.toml'])

export class DiscoveryError extends Error {}

const byteLength = (s) => new TextEncoder().encode(s).length

/** os.walk order: files of a directory (sorted) before its subdirectories (sorted). */
export function walkOrder(a, b) {
  const pa = a.split('/')
  const pb = b.split('/')
  for (let i = 0; i < Math.min(pa.length, pb.length); i++) {
    if (pa[i] === pb[i]) continue
    const aIsFile = i === pa.length - 1
    const bIsFile = i === pb.length - 1
    if (aIsFile !== bIsFile) return aIsFile ? -1 : 1
    return pa[i] < pb[i] ? -1 : 1
  }
  return pa.length - pb.length
}

/** Fnmatch-style glob ('*' and '?' also match '/', like Python's fnmatch). */
export function fnmatch(name, pattern) {
  let re = ''
  for (const ch of pattern) {
    if (ch === '*') re += '.*'
    else if (ch === '?') re += '.'
    else re += ch.replace(/[\\^$.|+()[\]{}]/g, '\\$&')
  }
  return new RegExp(`^${re}$`, 's').test(name)
}

function normalisePath(path) {
  const parts = String(path).replaceAll('\\', '/').split('/').filter((p) => p && p !== '.')
  if (parts.some((p) => p === '..')) throw new DiscoveryError(`${path}: relative parent paths are not allowed`)
  return parts.join('/')
}

/**
 * files: [{path, content}] -> { manifests: [{relPath, content, adapter, readSibling}], problems }
 * A single file with an unknown name is sniffed (CycloneDX or *.txt requirements).
 */
export function discover(files, exclude = []) {
  const problems = []
  if (!files.length) throw new DiscoveryError('no files provided')
  if (files.length > MAX_FILES) throw new DiscoveryError(`too many files (limit ${MAX_FILES})`)
  let total = 0
  const all = files.map((f) => {
    const size = byteLength(f.content)
    if (size > MAX_FILE_BYTES) throw new DiscoveryError(`${f.path}: file larger than ${MAX_FILE_BYTES / 1024 / 1024} MB`)
    total += size
    return { path: normalisePath(f.path), content: f.content }
  })
  if (total > MAX_TOTAL_BYTES) throw new DiscoveryError(`files larger than ${MAX_TOTAL_BYTES / 1024 / 1024} MB in total`)
  const byPath = new Map(all.map((f) => [f.path, f]))

  const siblingReader = (relPath) => (name) => {
    if (!SIBLING_ALLOWLIST.has(name)) return null
    const dir = relPath.includes('/') ? relPath.slice(0, relPath.lastIndexOf('/') + 1) : ''
    return byPath.get(dir + name)?.content ?? null
  }

  if (all.length === 1) {
    const f = all[0]
    const filename = f.path.slice(f.path.lastIndexOf('/') + 1)
    const parent = f.path.includes('/') ? f.path.split('/').slice(-2, -1)[0] : ''
    const adapter = adapterFor(filename, parent) ?? sniffAdapter(f.content, filename)
    if (!adapter) throw new DiscoveryError(`unsupported file: ${filename}`)
    return { manifests: [{ relPath: filename, content: f.content, adapter, readSibling: siblingReader(f.path) }], problems }
  }

  const manifests = []
  const sorted = [...all].sort((a, b) => walkOrder(a.path, b.path))
  for (const f of sorted) {
    const parts = f.path.split('/')
    const dirs = parts.slice(0, -1)
    if (dirs.length > MAX_DEPTH || dirs.some((d) => SKIP_DIRS.has(d) || d.startsWith('.'))) continue
    const filename = parts[parts.length - 1]
    const adapter = adapterFor(filename, dirs[dirs.length - 1] ?? '')
    if (!adapter) continue
    const dirPrefix = dirs.length ? dirs.join('/') + '/' : ''
    if ((SUPERSEDED_BY[filename] ?? []).some((sup) => byPath.has(dirPrefix + sup))) continue
    if (exclude.some((p) => fnmatch(f.path, p))) continue
    manifests.push({ relPath: f.path, content: f.content, adapter, readSibling: siblingReader(f.path) })
  }
  if (!manifests.length) problems.push(problem('no_manifests', 'no supported manifest or lockfile found', null))
  return { manifests, problems }
}
