import { useState } from 'react'
import { GitHubIcon, MoonIcon, ShieldIcon, SunIcon } from './Icons.jsx'
import { currentTheme, setTheme } from '../demo/theme.js'
import { REPO_URL } from '../links.js'

const NAV = [
  ['#demo', 'Demo'],
  ['#como-funciona', 'Cómo funciona'],
  ['#arquitectura', 'Arquitectura'],
  ['#demo-vs-local', 'Demo vs CLI'],
]

export default function Header() {
  const [theme, setThemeState] = useState(currentTheme)
  const toggle = () => {
    const next = theme === 'dark' ? 'light' : 'dark'
    setTheme(next)
    setThemeState(next)
  }
  return (
    <header className="sticky top-0 z-30 border-b border-slate-200/80 bg-white/90 backdrop-blur dark:border-slate-800 dark:bg-slate-950/90">
      <div className="mx-auto flex h-14 max-w-6xl items-center justify-between gap-4 px-4 sm:px-6">
        <a href="#top" className="flex items-center gap-2 font-semibold text-slate-900 dark:text-white">
          <ShieldIcon className="size-7" />
          <span>DepGuard</span>
          <span className="chip bg-accent-50 text-accent-800 dark:bg-accent-800/30 dark:text-accent-100">demo</span>
        </a>
        <nav aria-label="Secciones" className="hidden items-center gap-1 md:flex">
          {NAV.map(([href, label]) => (
            <a key={href} href={href} className="btn-ghost text-sm">
              {label}
            </a>
          ))}
        </nav>
        <div className="flex items-center gap-1">
          <button
            type="button"
            onClick={toggle}
            className="btn-ghost"
            aria-label={theme === 'dark' ? 'Usar tema claro' : 'Usar tema oscuro'}
          >
            {theme === 'dark' ? <SunIcon /> : <MoonIcon />}
          </button>
          <a href={REPO_URL} className="btn-secondary px-3" target="_blank" rel="noopener noreferrer">
            <GitHubIcon />
            <span className="hidden sm:inline">Código</span>
          </a>
        </div>
      </div>
    </header>
  )
}
