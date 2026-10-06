// pip requirements files. Mirrors dep_guard/adapters/pypi_requirements.py.
// Only exact pins (== / ===) are queried; everything else is UNRESOLVED.

import { build, normalizePypiName } from '../purl.js'
import { ComponentStatus, Scope, makeComponent, problem } from '../models.js'
import { clean } from '../textutil.js'
import { location } from './base.js'

const NAME = /^(?:.*[-_.])?requirements(?:[-_.].*)?\.txt$/i
const DEV_HINT = /(^|[-_.])(dev|develop|tests?|testing|lint|docs?|ci)([-_.]|$)/i
const INLINE_COMMENT = /(^|\s)#.*$/
const INCLUDE_OPTS = ['-r', '--requirement', '-c', '--constraint']
const EDITABLE_OPTS = ['-e', '--editable']

// --- PEP 508 subset (what `packaging.requirements.Requirement` accepts in practice)
const RE_NAME = /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?/
const RE_OP = /^(===|~=|==|!=|<=|>=|<|>)/
const RE_VERSION = /^[A-Za-z0-9_.*+!-]+/

/** Returns { name, extras, specs: [{op, version}], url, marker } or null if invalid. */
export function parseRequirement(text) {
  let s = text.trim()
  const name = RE_NAME.exec(s)?.[0]
  if (!name) return null
  s = s.slice(name.length).trimStart()
  const extras = []
  if (s.startsWith('[')) {
    const end = s.indexOf(']')
    if (end < 0) return null
    const inner = s.slice(1, end).trim()
    if (inner) {
      for (const e of inner.split(',')) {
        if (!RE_NAME.test(e.trim()) || RE_NAME.exec(e.trim())[0] !== e.trim()) return null
        extras.push(e.trim())
      }
    }
    s = s.slice(end + 1).trimStart()
  }
  let url = null
  const specs = []
  if (s.startsWith('@')) {
    const rest = s.slice(1).trimStart()
    const m = /^(\S+)(.*)$/.exec(rest)
    if (!m) return null
    url = m[1]
    s = m[2]
    if (s && !/^\s+;/.test(s) && s.trim()) return null
    s = s.trimStart()
  } else {
    let body = s
    let paren = false
    if (body.startsWith('(')) {
      const end = body.indexOf(')')
      if (end < 0) return null
      paren = true
      s = body.slice(end + 1).trimStart()
      body = body.slice(1, end)
    }
    let rest = body.trimStart()
    while (rest && RE_OP.test(rest)) {
      const op = RE_OP.exec(rest)[0]
      rest = rest.slice(op.length).trimStart()
      const version = RE_VERSION.exec(rest)?.[0]
      if (!version) return null
      specs.push({ op, version })
      rest = rest.slice(version.length).trimStart()
      if (rest.startsWith(',')) {
        rest = rest.slice(1).trimStart()
        if (!RE_OP.test(rest)) return null
      } else break
    }
    if (paren) {
      if (rest.trim()) return null
    } else s = rest
  }
  let marker = null
  if (s.startsWith(';')) {
    marker = s.slice(1).trim()
    if (!marker) return null
    s = ''
  }
  if (s.trim()) return null
  return { name, extras, specs, url, marker }
}

function logicalLines(content) {
  const out = []
  let buf = ''
  let start = 0
  const lines = content.split(/\r\n|\r|\n/)
  if (lines.length && lines[lines.length - 1] === '') lines.pop()
  lines.forEach((raw, idx) => {
    const i = idx + 1
    if (!buf) start = i
    const line = raw.trimEnd()
    if (line.endsWith('\\')) {
      buf += line.slice(0, -1) + ' '
      return
    }
    buf += line
    const text = buf.replace(INLINE_COMMENT, '').trim()
    buf = ''
    if (text) out.push([start, text])
  })
  if (buf.trim()) out.push([start, buf.replace(INLINE_COMMENT, '').trim()])
  return out
}

export const requirementsAdapter = {
  id: 'pip-requirements',
  matches(filename, parentDir) {
    if (NAME.test(filename)) return true
    return parentDir.toLowerCase() === 'requirements' && filename.toLowerCase().endsWith('.txt')
  },
  parse(content, ctx) {
    const result = { components: [], problems: [] }
    const stem = ctx.relPath.slice(ctx.relPath.lastIndexOf('/') + 1)
    const scope = DEV_HINT.test(stem.replace('requirements', '')) ? Scope.DEV : Scope.PROD

    for (const [lineno, line] of logicalLines(content)) {
      if (line.startsWith('-')) {
        // Never echo option values: index URLs frequently embed credentials.
        const opt = line.split(/\s+/, 1)[0].split('=', 1)[0]
        if (INCLUDE_OPTS.includes(opt)) {
          result.problems.push(
            problem(
              'include_not_followed',
              `line ${lineno}: nested requirement/constraint files are not followed; ` +
                'scan them directly (directory scans find them automatically)',
              ctx.relPath,
            ),
          )
        } else if (EDITABLE_OPTS.includes(opt)) {
          result.problems.push(problem('editable_skipped', `line ${lineno}: editable install skipped`, ctx.relPath))
        }
        continue
      }
      const spec = line.split(/\s+--?\w/, 1)[0].trim()
      const req = parseRequirement(spec)
      if (!req) {
        result.problems.push(
          problem('invalid_requirement', `line ${lineno}: not a valid PEP 508 requirement`, ctx.relPath),
        )
        continue
      }
      const name = normalizePypiName(req.name)
      const comp = makeComponent({
        ecosystem: 'PyPI',
        name,
        purl: build('PyPI', name),
        direct: true,
        scope,
        locations: location(ctx, lineno),
        paths: [[name]],
      })
      const s = req.specs
      if (req.url) comp.unresolvedReason = 'direct URL reference'
      else if (s.length === 1 && ['==', '==='].includes(s[0].op) && !s[0].version.includes('*'))
        comp.version = s[0].version
      else if (!s.length) comp.unresolvedReason = 'no version specified'
      else {
        // packaging's str(SpecifierSet): specifiers sorted and comma-joined.
        const joined = s
          .map((x) => x.op + x.version)
          .sort()
          .join(',')
        comp.unresolvedReason = `not pinned (${clean(joined, 80)})`
      }
      if (comp.version === null) comp.status = ComponentStatus.UNRESOLVED
      result.components.push(comp)
    }
    return result
  },
}
