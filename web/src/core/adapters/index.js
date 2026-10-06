// Adapter registry. Mirrors dep_guard/adapters/__init__.py.

import { cycloneDxAdapter } from './cyclonedx.js'
import { packageJsonAdapter, packageLockAdapter } from './npm.js'
import { poetryLockAdapter, uvLockAdapter } from './pypiLocks.js'
import { requirementsAdapter } from './requirements.js'

export { ParseError } from './base.js'

export const ADAPTERS = [
  packageLockAdapter,
  packageJsonAdapter,
  poetryLockAdapter,
  uvLockAdapter,
  requirementsAdapter,
  cycloneDxAdapter,
]

// A lockfile in the same directory supersedes the manifest it was generated from.
export const SUPERSEDED_BY = { 'package.json': ['package-lock.json', 'npm-shrinkwrap.json'] }

export const adapterFor = (filename, parentDir = '') => ADAPTERS.find((a) => a.matches(filename, parentDir)) ?? null

/** For a single file with a non-standard name. */
export function sniffAdapter(content, filename = '') {
  const head = content.trimStart().slice(0, 4096)
  if (head.startsWith('{') && content.slice(0, 65536).includes('"bomFormat"')) return cycloneDxAdapter
  if (filename.toLowerCase().endsWith('.txt')) return requirementsAdapter
  return null
}
