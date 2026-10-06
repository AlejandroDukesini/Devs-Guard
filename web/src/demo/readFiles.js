// Turn browser File objects into {path, content} for the engine.
// Files are filtered by name *before* reading, so dropping a whole project
// folder (with node_modules) does not read thousands of irrelevant files.

import { adapterFor } from '../core/adapters/index.js'
import { MAX_FILE_BYTES, MAX_FILES } from '../core/discovery.js'

const SKIP = /(^|\/)(node_modules|\.git|venv|\.venv|env|dist|build|target|vendor|__pycache__)(\/|$)/
const EXTRA = new Set(['pyproject.toml'])

export function isRelevant(path) {
  if (SKIP.test(path)) return false
  const parts = path.split('/')
  const name = parts[parts.length - 1]
  return EXTRA.has(name) || adapterFor(name, parts[parts.length - 2] ?? '') !== null
}

/** -> { files: [{path, content}], skipped: [messages] } */
export async function readFiles(fileList, { singleFileAnyName = false } = {}) {
  const all = [...fileList]
  const skipped = []
  const chosen = []
  for (const file of all) {
    const path = (file.webkitRelativePath || file.name).replaceAll('\\', '/')
    // A single explicitly chosen file may have any name (sniffed by the engine).
    if (!(singleFileAnyName && all.length === 1) && !isRelevant(path)) continue
    if (file.size > MAX_FILE_BYTES) {
      skipped.push(`${path}: más de ${MAX_FILE_BYTES / 1024 / 1024} MB, omitido`)
      continue
    }
    chosen.push({ file, path })
  }
  if (chosen.length > MAX_FILES) {
    skipped.push(`Solo se leen los primeros ${MAX_FILES} archivos relevantes`)
    chosen.length = MAX_FILES
  }
  // Strip a common top-level folder ("my-project/package.json" -> "package.json").
  const tops = new Set(chosen.map(({ path }) => (path.includes('/') ? path.split('/')[0] : '')))
  const strip = tops.size === 1 && !tops.has('') ? [...tops][0].length + 1 : 0
  const files = await Promise.all(chosen.map(async ({ file, path }) => ({ path: path.slice(strip), content: await file.text() })))
  return { files, skipped }
}
