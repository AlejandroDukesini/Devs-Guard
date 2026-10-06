// Minimal Package URL helpers. Mirrors dep_guard/purl.py.

export const PURL_TYPE_TO_ECOSYSTEM = {
  pypi: 'PyPI',
  npm: 'npm',
  maven: 'Maven',
  golang: 'Go',
  cargo: 'crates.io',
  nuget: 'NuGet',
  gem: 'RubyGems',
  composer: 'Packagist',
  pub: 'Pub',
  hex: 'Hex',
}
const ECOSYSTEM_TO_PURL_TYPE = Object.fromEntries(
  Object.entries(PURL_TYPE_TO_ECOSYSTEM).map(([k, v]) => [v, k]),
)

export const normalizePypiName = (name) => name.replace(/[-_.]+/g, '-').toLowerCase()

// Python's urllib.parse.quote(s, safe=...) for the characters that matter here.
function quote(s, safe = '') {
  const keep = /[A-Za-z0-9_.~-]/
  let out = ''
  for (const ch of s) {
    if (keep.test(ch) || safe.includes(ch)) out += ch
    else
      out += Array.from(new TextEncoder().encode(ch))
        .map((b) => '%' + b.toString(16).toUpperCase().padStart(2, '0'))
        .join('')
  }
  return out
}

/** Versionless purl for a package. */
export function build(ecosystem, name) {
  const ptype = ECOSYSTEM_TO_PURL_TYPE[ecosystem] ?? ecosystem.toLowerCase()
  if (ptype === 'pypi') return `pkg:pypi/${normalizePypiName(name)}`
  if (ptype === 'npm' && name.startsWith('@') && name.includes('/')) {
    const i = name.indexOf('/')
    return `pkg:npm/${quote(name.slice(0, i))}/${quote(name.slice(i + 1))}`
  }
  if (ptype === 'maven' && name.includes(':')) {
    const i = name.indexOf(':')
    return `pkg:maven/${quote(name.slice(0, i), '.')}/${quote(name.slice(i + 1), '.')}`
  }
  return `pkg:${ptype}/${quote(name, '/.')}`
}

function unquote(s) {
  try {
    return decodeURIComponent(s)
  } catch {
    return s
  }
}

export function parse(purl) {
  if (typeof purl !== 'string' || !purl.startsWith('pkg:') || purl.length > 2048) return null
  let rest = purl.slice(4).replace(/^\/+/, '')
  rest = rest.split('#', 1)[0].split('?', 1)[0]
  let version = null
  const lastSegment = rest.slice(rest.lastIndexOf('/') + 1)
  if (lastSegment.includes('@')) {
    const at = rest.lastIndexOf('@')
    version = unquote(rest.slice(at + 1)) || null
    rest = rest.slice(0, at)
  }
  const parts = rest.split('/').filter(Boolean)
  if (parts.length < 2) return null
  const type = parts[0].toLowerCase()
  let name = unquote(parts[parts.length - 1])
  const namespace = parts.slice(1, -1).map(unquote).join('/') || null
  if (type === 'pypi') name = normalizePypiName(name)
  const ecosystem = PURL_TYPE_TO_ECOSYSTEM[type] ?? null
  const osvName = !namespace ? name : type === 'maven' ? `${namespace}:${name}` : `${namespace}/${name}`
  return { type, namespace, name, version, ecosystem, osvName }
}
