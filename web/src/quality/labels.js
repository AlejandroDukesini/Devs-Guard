// Spanish labels and styles for the quality center. Values stay in English.

import { CERT_STATUS } from './certificate.js'

export const STATUS_META = {
  passed: { label: 'Aprobada', bar: 'bg-emerald-600', text: 'text-emerald-700 dark:text-emerald-400' },
  failed: { label: 'Fallida', bar: 'bg-red-600', text: 'text-red-700 dark:text-red-400' },
  error: { label: 'Error de ejecución', bar: 'bg-fuchsia-600', text: 'text-fuchsia-700 dark:text-fuchsia-400' },
  skipped: { label: 'Omitida', bar: 'bg-slate-400', text: 'text-slate-600 dark:text-slate-400' },
}
export const STATUS_ORDER = ['passed', 'failed', 'error', 'skipped']

export const CATEGORY_LABEL = {
  unit: 'Unitarias',
  integration: 'Integración',
  functional: 'Funcionales',
  negative: 'Negativas',
  regression: 'Regresión',
  performance: 'Rendimiento',
  integrity: 'Integridad y persistencia',
  dependencies: 'Dependencias',
}

export const SEVERITY_LABEL = { critical: 'Crítica', high: 'Alta', medium: 'Media', low: 'Baja' }

export const CERT_META = {
  [CERT_STATUS.APPROVED]: {
    title: 'Evaluado: pruebas de seguridad superadas',
    style: 'border-emerald-300 bg-emerald-50 text-emerald-900 dark:border-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-200',
  },
  [CERT_STATUS.NOT_APPROVED]: {
    title: 'No aprobado',
    style: 'border-red-300 bg-red-50 text-red-900 dark:border-red-900 dark:bg-red-950/40 dark:text-red-200',
  },
  [CERT_STATUS.INSUFFICIENT]: {
    title: 'Evidencia insuficiente',
    style: 'border-amber-300 bg-amber-50 text-amber-900 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-200',
  },
  [CERT_STATUS.OUTDATED]: {
    title: 'Corresponde a una versión anterior',
    style: 'border-amber-300 bg-amber-50 text-amber-900 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-200',
  },
  [CERT_STATUS.NOT_EVALUATED]: {
    title: 'No evaluado',
    style: 'border-slate-300 bg-slate-50 text-slate-800 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200',
  },
}

export const formatDate = (iso) =>
  iso ? new Date(iso).toLocaleString('es-ES', { dateStyle: 'medium', timeStyle: 'medium' }) : 'no disponible'

export const formatMs = (ms) => (ms >= 1000 ? `${(ms / 1000).toFixed(1)} s` : `${Math.round(ms)} ms`)
