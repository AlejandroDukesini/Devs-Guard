import { useMemo, useState } from 'react'
import { CATEGORIES, SEVERITIES } from '../quality/runner.js'
import { REPORT_SCHEMA, verifyReport } from '../quality/report.js'
import { evaluateCertificate } from '../quality/certificate.js'
import { BUILD } from '../quality/buildInfo.js'
import { CATEGORY_LABEL, CERT_META, SEVERITY_LABEL, STATUS_META, STATUS_ORDER, formatDate, formatMs } from '../quality/labels.js'
import { downloadQualityReport } from '../demo/exports.js'
import { AlertIcon, CheckIcon, ChevronIcon, DownloadIcon, MinusIcon, PlayIcon, Spinner, UploadIcon, XIcon } from './Icons.jsx'

const STATUS_ICON = { passed: CheckIcon, failed: XIcon, error: AlertIcon, skipped: MinusIcon }
const MAX_VERIFY_BYTES = 2 * 1024 * 1024

export function StatusBadge({ status }) {
  const Icon = STATUS_ICON[status]
  return (
    <span className={`inline-flex items-center gap-1 text-sm font-medium ${STATUS_META[status].text}`}>
      <Icon className="size-4" /> {STATUS_META[status].label}
    </span>
  )
}

/** Stacked bar of the four outcomes, with a legend (never color alone). */
function StatusBar({ counts, total, legend = true }) {
  return (
    <div>
      <div className="flex h-3 gap-0.5 overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800" role="img"
        aria-label={STATUS_ORDER.map((s) => `${STATUS_META[s].label}: ${counts[s]}`).join(', ')}>
        {STATUS_ORDER.filter((s) => counts[s]).map((s) => (
          <span key={s} className={STATUS_META[s].bar} style={{ width: `${(counts[s] / total) * 100}%` }} title={`${STATUS_META[s].label}: ${counts[s]}`} />
        ))}
      </div>
      {legend && (
        <ul className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-600 dark:text-slate-400">
          {STATUS_ORDER.map((s) => (
            <li key={s} className="flex items-center gap-1.5">
              <span className={`size-2.5 rounded-sm ${STATUS_META[s].bar}`} aria-hidden="true" />
              {STATUS_META[s].label} <strong className="text-slate-900 dark:text-white">{counts[s]}</strong>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

function Tile({ label, value, hint }) {
  return (
    <div className="card p-3">
      <p className="label">{label}</p>
      <p className="mt-1 text-2xl font-semibold text-slate-900 dark:text-white">{value}</p>
      {hint && <p className="text-xs text-slate-500">{hint}</p>}
    </div>
  )
}

function Summary({ report }) {
  const s = report.summary
  const cert = evaluateCertificate(report, BUILD)
  const wall = new Date(report.finished_at) - new Date(report.started_at)
  return (
    <div className="flex flex-col gap-4">
      <div className={`rounded-xl border p-4 ${CERT_META[cert.status].style}`}>
        <p className="text-xl font-semibold">{CERT_META[cert.status].title}</p>
        <ul className="mt-1 space-y-0.5 text-sm">
          {cert.reasons.map((r) => (
            <li key={r}>{r}</li>
          ))}
        </ul>
      </div>
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        <Tile label="Pruebas" value={s.total} hint={`${s.executed} ejecutadas`} />
        <Tile label="Aprobación" value={s.pass_rate === null ? 'n/d' : `${s.pass_rate} %`} hint="aprobadas / ejecutadas" />
        <Tile label="Duración" value={formatMs(wall)} hint={`${s.coverage} % ejecutado`} />
        <Tile label="Última ejecución" value={new Date(report.finished_at).toLocaleTimeString('es-ES')} hint={new Date(report.finished_at).toLocaleDateString('es-ES')} />
      </div>
      <div className="card p-4">
        <StatusBar counts={s} total={s.total} />
      </div>
    </div>
  )
}

function Categories({ report }) {
  return (
    <div className="card overflow-x-auto">
      <table className="w-full min-w-[22rem] text-sm">
        <caption className="sr-only">Resultados por categoría</caption>
        <thead>
          <tr className="border-b border-slate-200 text-left dark:border-slate-800">
            <th scope="col" className="label p-3">Categoría</th>
            <th scope="col" className="label w-1/2 p-3">Resultado</th>
            <th scope="col" className="label p-3 text-right">Aprobadas</th>
          </tr>
        </thead>
        <tbody>
          {CATEGORIES.map((c) => {
            const counts = report.summary.by_category[c]
            const total = STATUS_ORDER.reduce((n, s) => n + counts[s], 0)
            if (!total) return null
            return (
              <tr key={c} className="border-b border-slate-200 last:border-0 dark:border-slate-800">
                <th scope="row" className="p-3 text-left font-medium text-slate-900 dark:text-white">{CATEGORY_LABEL[c]}</th>
                <td className="p-3"><StatusBar counts={counts} total={total} legend={false} /></td>
                <td className="p-3 text-right font-mono">{counts.passed}/{total}</td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

function ResultRow({ r }) {
  const [open, setOpen] = useState(r.status === 'failed' || r.status === 'error')
  return (
    <li className="border-b border-slate-200 last:border-0 dark:border-slate-800">
      <button type="button" onClick={() => setOpen((v) => !v)} aria-expanded={open}
        className="grid w-full grid-cols-[auto_1fr_auto] items-center gap-x-3 gap-y-1 px-3 py-2.5 text-left hover:bg-slate-50 dark:hover:bg-slate-800/40">
        <ChevronIcon open={open} className="size-3.5 text-slate-400" />
        <span className="min-w-0">
          <span className="font-mono text-xs text-slate-500">{r.id}</span>{' '}
          <span className="font-medium text-slate-900 dark:text-white">{r.name}</span>
        </span>
        <StatusBadge status={r.status} />
      </button>
      {open && (
        <div className="space-y-2 bg-slate-50 px-4 py-3 text-sm dark:bg-slate-900/60">
          <p className="text-slate-700 dark:text-slate-300">{r.description}</p>
          <p className="flex flex-wrap gap-x-4 text-xs text-slate-500">
            <span>Severidad: {SEVERITY_LABEL[r.severity]}</span>
            <span>Duración: {formatMs(r.duration_ms)}</span>
            <span>{formatDate(r.started_at)}</span>
          </p>
          <div>
            <p className="label mb-1">Evidencia</p>
            <ul className="space-y-0.5 font-mono text-xs break-words text-slate-700 dark:text-slate-300">
              {r.evidence.map((e, i) => (
                <li key={i}>{e}</li>
              ))}
            </ul>
          </div>
          {r.recommendation && (
            <div>
              <p className="label mb-1">Corrección recomendada</p>
              <p>{r.recommendation}</p>
            </div>
          )}
        </div>
      )}
    </li>
  )
}

function Select({ label, value, onChange, options }) {
  return (
    <label className="flex flex-col gap-1 text-xs text-slate-500">
      {label}
      <select aria-label={label} value={value} onChange={(e) => onChange(e.target.value)}
        className="rounded-md border border-slate-300 bg-white px-2 py-1.5 text-sm text-slate-800 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-200">
        <option value="all">Todas</option>
        {options.map(([v, text]) => (
          <option key={v} value={v}>{text}</option>
        ))}
      </select>
    </label>
  )
}

function Results({ report }) {
  const [filter, setFilter] = useState({ category: 'all', status: 'all', severity: 'all' })
  const set = (k) => (v) => setFilter((f) => ({ ...f, [k]: v }))
  const visible = report.results.filter(
    (r) =>
      (filter.category === 'all' || r.category === filter.category) &&
      (filter.status === 'all' || r.status === filter.status) &&
      (filter.severity === 'all' || r.severity === filter.severity),
  )
  return (
    <section className="card overflow-hidden" aria-label="Resultados detallados">
      <div className="grid grid-cols-1 gap-3 border-b border-slate-200 p-3 sm:grid-cols-3 dark:border-slate-800">
        <Select label="Categoría" value={filter.category} onChange={set('category')} options={CATEGORIES.map((c) => [c, CATEGORY_LABEL[c]])} />
        <Select label="Estado" value={filter.status} onChange={set('status')} options={STATUS_ORDER.map((s) => [s, STATUS_META[s].label])} />
        <Select label="Severidad" value={filter.severity} onChange={set('severity')} options={SEVERITIES.map((s) => [s, SEVERITY_LABEL[s]])} />
      </div>
      {CATEGORIES.map((c) => {
        const rows = visible.filter((r) => r.category === c)
        if (!rows.length) return null
        return (
          <div key={c}>
            <h4 className="label bg-slate-50 px-3 py-2 dark:bg-slate-900/60">{CATEGORY_LABEL[c]} ({rows.length})</h4>
            <ul>
              {rows.map((r) => (
                <ResultRow key={r.id} r={r} />
              ))}
            </ul>
          </div>
        )
      })}
      {!visible.length && <p className="p-4 text-sm text-slate-500">Ninguna prueba con estos filtros.</p>}
    </section>
  )
}

function History({ reports, selected, onSelect }) {
  return (
    <div className="card overflow-x-auto">
      <table className="w-full min-w-[26rem] text-sm">
        <caption className="sr-only">Historial de ejecuciones en este navegador</caption>
        <thead>
          <tr className="border-b border-slate-200 text-left dark:border-slate-800">
            <th scope="col" className="label p-3">Fecha</th>
            <th scope="col" className="label p-3">Ejecución</th>
            <th scope="col" className="label w-1/3 p-3">Resultado</th>
            <th scope="col" className="label p-3 text-right">Aprobación</th>
          </tr>
        </thead>
        <tbody>
          {reports.map((r) => (
            <tr key={r.run_id} className={`border-b border-slate-200 last:border-0 dark:border-slate-800 ${r.run_id === selected ? 'bg-accent-50/60 dark:bg-accent-800/20' : ''}`}>
              <td className="p-3 whitespace-nowrap">{formatDate(r.finished_at)}</td>
              <td className="p-3">
                <button type="button" className="font-mono text-xs text-accent-700 hover:underline dark:text-accent-500"
                  aria-pressed={r.run_id === selected} onClick={() => onSelect(r.run_id)}>
                  {r.run_id.slice(0, 8)}
                </button>
              </td>
              <td className="p-3"><StatusBar counts={r.summary} total={r.summary.total} legend={false} /></td>
              <td className="p-3 text-right font-mono">{r.summary.pass_rate === null ? 'n/d' : `${r.summary.pass_rate} %`}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function VerifyReport() {
  const [state, setState] = useState(null)
  const onFile = async (file) => {
    if (!file) return
    if (file.size > MAX_VERIFY_BYTES) return setState({ ok: false, text: 'Archivo demasiado grande.' })
    let data
    try {
      data = JSON.parse(await file.text())
    } catch {
      return setState({ ok: false, text: 'No es un JSON válido.' })
    }
    const { valid, reason } = await verifyReport(data)
    if (!valid) return setState({ ok: false, text: `Informe no válido: ${reason}.` })
    const cert = evaluateCertificate(data, BUILD)
    setState({ ok: true, text: `Huella válida. Ejecución ${data.run_id.slice(0, 8)}: ${CERT_META[cert.status].title.toLowerCase()}.` })
  }
  return (
    <div className="flex flex-wrap items-center gap-3">
      <label className="btn-secondary cursor-pointer py-1.5">
        <UploadIcon className="size-4" /> Verificar un informe
        <input type="file" accept="application/json,.json" className="sr-only" onChange={(e) => onFile(e.target.files[0])} />
      </label>
      {state && (
        <p role="status" className={`text-sm ${state.ok ? 'text-emerald-700 dark:text-emerald-400' : 'text-red-700 dark:text-red-400'}`}>
          {state.text}
        </p>
      )}
    </div>
  )
}

export default function QualityCenter({ quality }) {
  const { history, run, start } = quality
  const [selectedId, setSelectedId] = useState(null)
  const latest = history.reports[0] ?? null
  const report = useMemo(
    () => history.reports.find((r) => r.run_id === selectedId) ?? latest,
    [history.reports, selectedId, latest],
  )
  const running = run.phase === 'running'
  const p = run.progress

  return (
    <section id="calidad" className="scroll-mt-16 border-t border-slate-200 py-16 dark:border-slate-800">
      <div className="mx-auto max-w-6xl px-4 sm:px-6">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <h2 className="section-title">Centro de seguridad y calidad</h2>
          <button type="button" className="btn-primary" onClick={start} disabled={running}>
            {running ? <Spinner /> : <PlayIcon />} Ejecutar pruebas de seguridad
          </button>
        </div>

        {running && p && (
          <div className="mt-6 card p-4" aria-live="polite">
            <div className="flex justify-between text-sm">
              <span>Ejecutando {p.current ?? ''}</span>
              <span className="font-mono">{p.done}/{p.total || '…'}</span>
            </div>
            <div role="progressbar" aria-label="Progreso de las pruebas" aria-valuemin={0} aria-valuemax={p.total || 1} aria-valuenow={p.done}
              className="mt-2 h-2 overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
              <div className="h-full bg-accent-600 transition-[width]" style={{ width: `${p.total ? (p.done / p.total) * 100 : 0}%` }} />
            </div>
          </div>
        )}
        {run.phase === 'error' && (
          <p role="alert" className="mt-6 card border-red-300 p-4 text-sm text-red-800 dark:border-red-900 dark:text-red-300">
            Error de ejecución: {run.error}
          </p>
        )}
        {!run.persisted && (
          <p className="mt-4 text-sm text-amber-700 dark:text-amber-400">El navegador no permite guardar el historial: el resultado solo dura esta sesión.</p>
        )}
        {history.rejected > 0 && (
          <p className="mt-4 text-sm text-amber-700 dark:text-amber-400">{history.rejected} ejecución(es) guardada(s) descartada(s): su huella no era válida.</p>
        )}

        {!report ? (
          history.loaded && !running && <p className="mt-6 card p-8 text-center text-slate-600 dark:text-slate-400">Sin ejecuciones todavía.</p>
        ) : (
          <div className="mt-6 flex flex-col gap-6">
            {report !== latest && (
              <p className="text-sm text-amber-700 dark:text-amber-400">
                Viendo una ejecución anterior.{' '}
                <button type="button" className="underline" onClick={() => setSelectedId(null)}>Ver la última</button>
              </p>
            )}
            <Summary report={report} />
            <div className="grid gap-6 lg:grid-cols-2">
              <div>
                <h3 className="label mb-2">Por categoría</h3>
                <Categories report={report} />
              </div>
              <div>
                <h3 className="label mb-2">Historial (este navegador)</h3>
                <History reports={history.reports} selected={report.run_id} onSelect={setSelectedId} />
              </div>
            </div>
            <div>
              <h3 className="label mb-2">Resultados detallados</h3>
              <Results key={report.run_id} report={report} />
            </div>
            <div className="flex flex-wrap items-center gap-3">
              <button type="button" className="btn-secondary py-1.5" onClick={() => downloadQualityReport(report)} title={REPORT_SCHEMA}>
                <DownloadIcon /> Informe completo (JSON)
              </button>
              <VerifyReport />
            </div>
          </div>
        )}
      </div>
    </section>
  )
}
