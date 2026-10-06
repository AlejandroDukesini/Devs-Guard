// Version comparison per ecosystem. Mirrors dep_guard/versions.py
// (which uses `packaging` for PEP 440). Only used to choose which fixed
// version applies; whether a version is affected is decided by OSV.

import { compareTuples } from './models.js'

const SEMVER =
  /^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/

const sign = (n) => (n < 0 ? -1 : n > 0 ? 1 : 0)

function semverKey(v) {
  const m = SEMVER.exec(v.trim())
  if (!m) return null
  return { core: [Number(m[1]), Number(m[2]), Number(m[3])], pre: m[4] ? m[4].split('.') : [] }
}

function comparePrerelease(a, b) {
  if (!a.length || !b.length) return sign(Number(!a.length) - Number(!b.length))
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    const x = a[i]
    const y = b[i]
    if (x === y) continue
    const xn = /^\d+$/.test(x)
    const yn = /^\d+$/.test(y)
    if (xn && yn) return sign(Number(x) - Number(y))
    if (xn !== yn) return xn ? -1 : 1
    return x < y ? -1 : 1
  }
  return sign(a.length - b.length)
}

export function compareSemver(a, b) {
  const ka = semverKey(a)
  const kb = semverKey(b)
  if (!ka || !kb) return null
  return compareTuples(ka.core, kb.core) || comparePrerelease(ka.pre, kb.pre)
}

// --- PEP 440 (same grammar and ordering as packaging.version.Version) -----

const PEP440 = new RegExp(
  '^\\s*v?' +
    '(?:(?<epoch>[0-9]+)!)?' +
    '(?<release>[0-9]+(?:\\.[0-9]+)*)' +
    '(?<pre>[-_.]?(?<pre_l>alpha|a|beta|b|preview|pre|c|rc)[-_.]?(?<pre_n>[0-9]+)?)?' +
    '(?<post>(?:-(?<post_n1>[0-9]+))|(?:[-_.]?(?<post_l>post|rev|r)[-_.]?(?<post_n2>[0-9]+)?))?' +
    '(?<dev>[-_.]?(?<dev_l>dev)[-_.]?(?<dev_n>[0-9]+)?)?' +
    '(?:\\+(?<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?' +
    '\\s*$',
  'i',
)
const NEG = -Infinity
const POS = Infinity
const PRE_ORDER = { a: 0, b: 1, rc: 2 }

function pep440Key(version) {
  const m = PEP440.exec(version)
  if (!m) return null
  const g = m.groups
  const release = g.release.split('.').map(Number)
  while (release.length > 1 && release[release.length - 1] === 0) release.pop()

  let pre = null
  if (g.pre_l) {
    const l = g.pre_l.toLowerCase()
    const letter = l === 'alpha' ? 'a' : l === 'beta' ? 'b' : ['c', 'pre', 'preview'].includes(l) ? 'rc' : l
    pre = [PRE_ORDER[letter], Number(g.pre_n ?? 0)]
  }
  const hasPost = Boolean(g.post)
  const post = hasPost ? Number(g.post_n1 ?? g.post_n2 ?? 0) : null
  const dev = g.dev_l ? Number(g.dev_n ?? 0) : null

  // packaging._cmpkey: a bare .devN sorts before pre-releases.
  const preKey = pre === null && post === null && dev !== null ? [NEG] : pre === null ? [POS] : pre
  const postKey = post === null ? [NEG] : [post]
  const devKey = dev === null ? [POS] : [dev]
  const localKey =
    g.local === undefined
      ? null
      : g.local
          .toLowerCase()
          .split(/[-_.]/)
          .map((part) => (/^\d+$/.test(part) ? [Number(part), ''] : [NEG, part]))
  return { epoch: Number(g.epoch ?? 0), release, preKey, postKey, devKey, localKey }
}

function compareLocal(a, b) {
  if (a === null && b === null) return 0
  if (a === null) return -1 // no local segment sorts before any local segment
  if (b === null) return 1
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    const c = compareTuples(a[i], b[i])
    if (c) return c
  }
  return sign(a.length - b.length)
}

export function comparePep440(a, b) {
  const ka = pep440Key(a)
  const kb = pep440Key(b)
  if (!ka || !kb) return null
  return (
    sign(ka.epoch - kb.epoch) ||
    compareTuples(ka.release, kb.release) ||
    compareTuples(ka.preKey, kb.preKey) ||
    compareTuples(ka.postKey, kb.postKey) ||
    compareTuples(ka.devKey, kb.devKey) ||
    compareLocal(ka.localKey, kb.localKey)
  )
}

/**
 * Conservative ordering for ecosystems without a dedicated comparator:
 * numeric segments compare numerically; ambiguous qualifiers -> null.
 * Mirrors versions.compare_generic in Python.
 */
export function compareGeneric(a, b) {
  const strip = (v) => (v.trim().startsWith('v') ? v.trim().slice(1) : v.trim())
  const ta = strip(a).split(/[.\-+_]/)
  const tb = strip(b).split(/[.\-+_]/)
  const isNum = (t) => /^\d+$/.test(t)
  for (let i = 0; i < Math.min(ta.length, tb.length); i++) {
    if (ta[i] === tb[i]) continue
    if (isNum(ta[i]) && isNum(tb[i])) return sign(Number(ta[i]) - Number(tb[i]))
    return null
  }
  const [rest, s] = ta.length > tb.length ? [ta.slice(tb.length), 1] : [tb.slice(ta.length), -1]
  if (rest.every(isNum)) return rest.some((t) => Number(t) !== 0) ? s : 0
  return null
}

/** -1/0/1, or null when the versions cannot be ordered reliably. */
export function compare(ecosystem, a, b) {
  if (ecosystem === 'PyPI') return comparePep440(a, b)
  if (ecosystem === 'npm') return compareSemver(a, b)
  return compareGeneric(a, b)
}

export const isSemver = (v) => semverKey(v) !== null
