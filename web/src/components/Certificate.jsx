import { CERT_STATUS, LIMITATIONS, SCOPE, evaluateCertificate } from '../quality/certificate.js'
import { PROJECT_NAME } from '../quality/report.js'
import { BUILD } from '../quality/buildInfo.js'
import { CATEGORY_LABEL, CERT_META, formatDate } from '../quality/labels.js'
import { CATEGORIES } from '../quality/runner.js'
import { downloadQualityReport } from '../demo/exports.js'
import { DownloadIcon, PrinterIcon, ShieldIcon } from './Icons.jsx'

// Printing hides everything but the certificate, always in light colours.
function printCertificate() {
  const root = document.documentElement
  const wasDark = root.classList.contains('dark')
  root.classList.add('print-certificate')
  root.classList.remove('dark')
  const restore = () => {
    root.classList.remove('print-certificate')
    root.classList.toggle('dark', wasDark)
    window.removeEventListener('afterprint', restore)
  }
  window.addEventListener('afterprint', restore)
  window.print()
}

function Field({ label, children, mono = false }) {
  return (
    <div className="min-w-0">
      <dt className="label">{label}</dt>
      <dd className={`mt-0.5 text-slate-900 dark:text-white ${mono ? 'font-mono text-xs break-all' : 'text-sm'}`}>{children}</dd>
    </div>
  )
}

export default function Certificate({ report }) {
  const cert = evaluateCertificate(report, BUILD)
  const meta = CERT_META[cert.status]
  const s = report?.summary
  const evaluated = report ? CATEGORIES.filter((c) => Object.values(s.by_category[c]).some(Boolean)) : []
  const commit = report?.build?.commit

  return (
    <section id="certificado" className="scroll-mt-16 border-t border-slate-200 py-16 dark:border-slate-800">
      <div className="mx-auto max-w-4xl px-4 sm:px-6">
        <div className="no-print flex flex-wrap items-end justify-between gap-4">
          <h2 className="section-title">Certificado de calidad y seguridad</h2>
          {report && (
            <div className="flex gap-2">
              <button type="button" className="btn-secondary py-1.5" onClick={printCertificate}>
                <PrinterIcon /> Imprimir / PDF
              </button>
              <button type="button" className="btn-secondary py-1.5" onClick={() => downloadQualityReport(report)}>
                <DownloadIcon /> Informe
              </button>
            </div>
          )}
        </div>

        <article id="certificado-doc" className="mt-6 card p-6 sm:p-8" aria-label="Certificado">
          <header className="flex items-start justify-between gap-4 border-b border-slate-200 pb-4 dark:border-slate-800">
            <div>
              <p className="label">Certificado de pruebas internas</p>
              <p className="mt-1 text-2xl font-semibold text-slate-900 dark:text-white">{PROJECT_NAME}</p>
            </div>
            <ShieldIcon className="size-10 shrink-0" />
          </header>

          <div className={`mt-5 rounded-xl border p-4 ${meta.style}`}>
            <p className="text-xl font-semibold" data-testid="cert-status">{meta.title}</p>
            <ul className="mt-1 space-y-0.5 text-sm">
              {cert.reasons.map((r) => (
                <li key={r}>{r}</li>
              ))}
            </ul>
          </div>

          {report && (
            <>
              <dl className="mt-6 grid gap-4 sm:grid-cols-2">
                <Field label="Identificador del certificado" mono>{cert.id}</Field>
                <Field label="Ejecución que lo respalda" mono>{report.run_id}</Field>
                <Field label="Versión evaluada" mono>
                  {commit ? `${commit.slice(0, 12)}${report.build.dirty ? ' + cambios sin commit' : ''}` : 'no disponible'}
                </Field>
                <Field label="Huella del código evaluado" mono>{report.build.fingerprint ?? 'no disponible'}</Field>
                <Field label="Fecha de emisión">{formatDate(report.finished_at)}</Field>
                <Field label="Ejecución de las pruebas">{formatDate(report.started_at)}</Field>
                <Field label="Pruebas">
                  {s.executed} ejecutadas de {s.total}: {s.passed} aprobadas, {s.failed} fallidas, {s.skipped} omitidas, {s.error} con error
                </Field>
                <Field label="Entorno">{report.environment}</Field>
              </dl>

              <div className="mt-6 grid gap-6 sm:grid-cols-2">
                <div>
                  <p className="label mb-1">Alcance</p>
                  <ul className="list-disc space-y-0.5 pl-5 text-sm">
                    {SCOPE.map((x) => (
                      <li key={x}>{x}</li>
                    ))}
                  </ul>
                  <p className="label mt-4 mb-1">Categorías evaluadas</p>
                  <p className="text-sm">{evaluated.map((c) => CATEGORY_LABEL[c]).join(' · ')}</p>
                </div>
                <div>
                  <p className="label mb-1">Limitaciones</p>
                  <ul className="list-disc space-y-0.5 pl-5 text-sm">
                    {LIMITATIONS.map((x) => (
                      <li key={x}>{x}</li>
                    ))}
                  </ul>
                </div>
              </div>

              <div className="mt-6 border-t border-slate-200 pt-4 dark:border-slate-800">
                <Field label="SHA-256 del informe" mono>{report.sha256}</Field>
                <p className="mt-2 text-xs text-slate-500">
                  Cubre el informe JSON completo (resultados, evidencias y huella del código evaluado). Demuestra que el informe no se
                  ha modificado; no mide la seguridad del código.
                </p>
              </div>
            </>
          )}

          <p className="mt-6 text-xs text-slate-500">
            {cert.status === CERT_STATUS.APPROVED
              ? 'Pruebas internas superadas. '
              : ''}
            No es una certificación externa ni acreditada.
          </p>
        </article>
      </div>
    </section>
  )
}
