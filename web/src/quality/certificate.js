// Turns a sealed quality report into a certificate status. The rules are
// deliberately strict: anything short of "every test of the suite ran and
// passed, on this exact build" is not an approval.

import { STATUS } from './runner.js'

export const CERT_STATUS = Object.freeze({
  NOT_EVALUATED: 'not_evaluated', // no run
  APPROVED: 'approved', // every test ran and passed on the current build
  NOT_APPROVED: 'not_approved', // at least one test failed
  INSUFFICIENT: 'insufficient', // skipped tests, execution errors or an incomplete suite
  OUTDATED: 'outdated', // passed, but on a different build than the one being served
})

export const SCOPE = [
  'Motor de análisis en JavaScript que ejecuta esta web (web/src/core)',
  'Paridad con el motor de referencia en Python mediante los casos golden compartidos',
  'Comportamiento ante fallos, entradas hostiles y límites',
  'Configuración de despliegue y dependencias de la web',
]

export const LIMITATIONS = [
  'Emitido automáticamente por la batería de pruebas del proyecto; complementa, no sustituye, una auditoría externa.',
  'El motor Python (CLI) se prueba en CI con pytest; aquí solo se verifica a través de los casos golden compartidos.',
  'Las fuentes externas (OSV, EPSS, KEV) se simulan, salvo en la comprobación de dependencias en vivo.',
  'Los tiempos de rendimiento dependen del equipo y del navegador que ejecuta la prueba.',
  'Superar estas pruebas no garantiza la ausencia de vulnerabilidades.',
]

export const certificateId = (report) => `DG-QC-${report.sha256.slice(0, 16).toUpperCase()}`

/**
 * report: sealed and verified report, or null. build: the build being served.
 * -> { status, reasons: [string], stale: boolean|null, id|null }
 */
export function evaluateCertificate(report, build) {
  if (!report) return { status: CERT_STATUS.NOT_EVALUATED, reasons: ['No se ha ejecutado ninguna prueba.'], stale: null, id: null }

  const s = report.summary
  const reasons = []
  const failed = report.results.filter((r) => r.status === STATUS.FAILED)
  const critical = failed.filter((r) => r.severity === 'critical')
  if (critical.length) reasons.push(`${critical.length} fallo(s) crítico(s): ${critical.map((r) => r.id).join(', ')}`)
  if (failed.length > critical.length) reasons.push(`${failed.length - critical.length} prueba(s) fallida(s) no críticas`)
  if (s.error) reasons.push(`${s.error} prueba(s) con error de ejecución`)
  const outOfScope = report.results.filter((r) => r.status === STATUS.SKIPPED && r.out_of_scope)
  const missing = report.results.filter((r) => r.status === STATUS.SKIPPED && !r.out_of_scope)
  if (missing.length) reasons.push(`Sin evidencia: ${missing.map((r) => `${r.id} (${r.evidence[0] ?? 'omitida'})`).join('; ')}`)
  if (s.total < report.suite_size) reasons.push(`Solo ${s.total} de ${report.suite_size} pruebas tienen resultado`)

  const stale = !build?.fingerprint || !report.build?.fingerprint ? null : build.fingerprint !== report.build.fingerprint
  if (stale === null) reasons.push('No se puede comprobar qué versión del código se evaluó.')
  if (stale) reasons.push('El código ha cambiado desde esta ejecución: el resultado corresponde a una versión anterior.')

  let status
  if (failed.length) status = CERT_STATUS.NOT_APPROVED
  else if (s.error || missing.length || s.total < report.suite_size || stale === null) status = CERT_STATUS.INSUFFICIENT
  else if (stale) status = CERT_STATUS.OUTDATED
  else status = CERT_STATUS.APPROVED

  if (status === CERT_STATUS.APPROVED)
    reasons.unshift(`${s.passed} de ${s.passed} pruebas de seguridad ejecutadas y superadas.`)
  if (outOfScope.length)
    reasons.push(
      `No aplica en este entorno: ${outOfScope.map((r) => r.id).join(', ')} (se verifica${outOfScope.length > 1 ? 'n' : ''} en la versión publicada).`,
    )
  return { status, reasons, stale, id: certificateId(report) }
}
