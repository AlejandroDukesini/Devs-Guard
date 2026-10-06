// Human labels and styles for the UI (Spanish). Engine values stay in English.

export const PRIORITY_STYLE = {
  P0: 'bg-red-600 text-white',
  P1: 'bg-orange-500 text-white',
  P2: 'bg-amber-300 text-amber-950',
  P3: 'bg-slate-200 text-slate-700 dark:bg-slate-700 dark:text-slate-200',
}

export const PRIORITY_MEANING = {
  P0: 'Actuar ya',
  P1: 'Corregir en este ciclo',
  P2: 'Planificar',
  P3: 'Mantener actualizado',
}

export const SEVERITY_STYLE = {
  CRITICAL: 'text-red-700 dark:text-red-400',
  HIGH: 'text-orange-700 dark:text-orange-400',
  MEDIUM: 'text-amber-700 dark:text-amber-300',
  LOW: 'text-slate-600 dark:text-slate-400',
  UNKNOWN: 'text-fuchsia-700 dark:text-fuchsia-400',
}

export const VERDICT = {
  PASS: {
    title: 'PASS',
    text: 'La política se cumple y todas las dependencias se pudieron comprobar.',
    style: 'border-emerald-300 bg-emerald-50 text-emerald-900 dark:border-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-200',
  },
  FAIL: {
    title: 'FAIL',
    text: 'Hay vulnerabilidades que incumplen la política.',
    style: 'border-red-300 bg-red-50 text-red-900 dark:border-red-900 dark:bg-red-950/40 dark:text-red-200',
  },
  INCOMPLETE: {
    title: 'INCOMPLETE',
    text: 'No se pudo comprobar todo. Esto no es un "sin vulnerabilidades".',
    style: 'border-amber-300 bg-amber-50 text-amber-900 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-200',
  },
}

export const STATUS_LABEL = {
  clean: 'sin avisos',
  vulnerable: 'vulnerable',
  unresolved: 'sin versión exacta',
  private: 'privada (no consultada)',
  error: 'no comprobada',
}

export const SOURCE_LABEL = { osv: 'OSV.dev', epss: 'FIRST EPSS', kev: 'CISA KEV' }

export function sourceState(value) {
  if (value === 'ok') return { ok: true, text: 'ok' }
  if (value === 'offline-cache') return { ok: true, text: 'instantánea' }
  if (value === 'not needed') return { ok: true, text: 'no necesario' }
  if (value === 'disabled') return { ok: true, text: 'desactivado' }
  return { ok: false, text: value.replace(/^error: /, '') }
}

export const DEFAULT_CONFIG = `# depguard.toml: la misma configuración que usa la CLI
[policy]
fail_on_priority = "P1"   # P0 | P1 | P2 | P3 | none
fail_on_kev = true
fail_on_incomplete = true
`
