// Identity of the code being built, injected into the app as __BUILD_INFO__.
// The quality report records it, and the certificate compares it with the
// build being served to detect results that belong to an older version.
//
// fingerprint = SHA-256 over "path\nsha256(content)\n" for every evaluated
// file, sorted by path, with line endings normalised to LF (so it is the
// same on Windows checkouts and on the Linux build machine).

import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

const REPO = fileURLToPath(new URL('..', import.meta.url))
export const EVALUATED = ['web/src', 'fixtures', 'web/package.json', 'web/package-lock.json', 'web/security-headers.js', 'web/index.html', 'netlify.toml']

function walk(path, out) {
  if (statSync(path).isDirectory()) for (const name of readdirSync(path)) walk(join(path, name), out)
  else out.push(path)
}

const sha256 = (data) => createHash('sha256').update(data).digest('hex')

function git(args) {
  try {
    return execFileSync('git', args, { cwd: REPO, encoding: 'utf-8', stdio: ['ignore', 'pipe', 'ignore'] }).trim()
  } catch {
    return null
  }
}

export function buildInfo() {
  const files = []
  for (const entry of EVALUATED) walk(join(REPO, entry), files)
  const lines = files
    .map((f) => relative(REPO, f).split(sep).join('/'))
    .sort()
    .map((rel) => `${rel}\n${sha256(readFileSync(join(REPO, rel), 'utf-8').replaceAll('\r\n', '\n'))}\n`)
  const commit = process.env.COMMIT_REF || git(['rev-parse', 'HEAD'])
  const status = git(['status', '--porcelain', '--', ...EVALUATED])
  return {
    commit,
    // Uncommitted changes in the evaluated files: the commit alone does not identify the code.
    dirty: status === null ? null : status.length > 0,
    fingerprint: sha256(lines.join('')),
    files: lines.length,
    built_at: new Date().toISOString(),
  }
}
