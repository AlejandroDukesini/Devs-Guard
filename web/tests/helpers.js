// Test helpers: load the shared fixtures (../fixtures) and serve the fake
// OSV/EPSS/KEV universe through an injectable fetch, like tests/osv_mock.py.

import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  FIXTURE_TODAY,
  createMockFetch as createSharedMockFetch,
  mockScanOptions,
  normalise,
} from '../src/quality/mockSources.js'

export const FIXTURES = fileURLToPath(new URL('../../fixtures/', import.meta.url))
export const TODAY = FIXTURE_TODAY
export const readJson = (rel) => JSON.parse(readFileSync(join(FIXTURES, rel), 'utf-8'))
export const readText = (rel) => readFileSync(join(FIXTURES, rel), 'utf-8')

/** All files of a fixture project as [{path, content}] (relative POSIX paths). */
export function projectFiles(project) {
  const root = join(FIXTURES, 'projects', project)
  const out = []
  const walk = (dir) => {
    for (const name of readdirSync(dir)) {
      const full = join(dir, name)
      if (statSync(full).isDirectory()) walk(full)
      else out.push({ path: relative(root, full).split(sep).join('/'), content: readFileSync(full, 'utf-8') })
    }
  }
  walk(root)
  return out
}

/** Fake fetch backed by fixtures/osv-mock. `state.fail[endpoint]` injects failures. */
export const createMockFetch = () =>
  createSharedMockFetch({
    index: readJson('osv-mock/index.json'),
    epss: readJson('osv-mock/epss.json'),
    kev: readJson('osv-mock/kev.json'),
    vuln: (id) => {
      try {
        return readText(`osv-mock/vulns/${id}.json`)
      } catch {
        return null
      }
    },
  })

export const scanOptions = mockScanOptions
export { normalise }
