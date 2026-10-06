// Sanitising untrusted text (package names, advisory summaries).
// Mirrors dep_guard/textutil.py. Code points are written as numbers on
// purpose: the source must never contain invisible characters.

const UNSAFE_RANGES = [
  [0x00, 0x08], // C0 controls (tab and newline are kept)
  [0x0b, 0x1f], // rest of C0, includes ESC and CR
  [0x7f, 0x9f], // DEL + C1 controls
  [0x200b, 0x200f], // zero-width space/joiners, LRM, RLM
  [0x202a, 0x202e], // bidi embeddings and overrides
  [0x2066, 0x2069], // bidi isolates
  [0xfeff, 0xfeff], // BOM / zero-width no-break space
]

const hex = (n) => `\\u{${n.toString(16)}}`
const UNSAFE = new RegExp(`[${UNSAFE_RANGES.map(([lo, hi]) => `${hex(lo)}-${hex(hi)}`).join('')}]`, 'gu')

export function clean(value, maxLen = 500, singleLine = true) {
  if (typeof value !== 'string') return ''
  let text = value.replace(UNSAFE, '')
  if (singleLine) text = text.split(/\s+/u).filter(Boolean).join(' ')
  const chars = Array.from(text) // count code points like Python's len()
  if (chars.length > maxLen) text = chars.slice(0, maxLen - 1).join('') + '…'
  return text
}

/** 1-based line of the first occurrence of `needle` (best effort). */
export function findLine(content, needle) {
  const idx = content.indexOf(needle)
  if (idx < 0) return null
  let line = 1
  for (let i = 0; i < idx; i++) if (content.charCodeAt(i) === 10) line++
  return line
}
