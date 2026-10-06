// Light/dark theme: follows the OS unless the visitor chooses. The choice is
// a per-browser convenience; storage may be unavailable (private mode).

const KEY = 'depguard-theme'

function read() {
  try {
    return localStorage.getItem(KEY)
  } catch {
    return null
  }
}

export function currentTheme() {
  const stored = read()
  if (stored === 'dark' || stored === 'light') return stored
  return globalThis.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

export function applyStoredTheme() {
  document.documentElement.classList.toggle('dark', currentTheme() === 'dark')
}

export function setTheme(theme) {
  try {
    localStorage.setItem(KEY, theme)
  } catch {
    // storage blocked: the choice simply won't persist
  }
  document.documentElement.classList.toggle('dark', theme === 'dark')
}
