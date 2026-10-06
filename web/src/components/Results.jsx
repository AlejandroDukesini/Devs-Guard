import { useMemo, useState } from 'react'
import { PRIORITIES } from '../core/models.js'
import { EXPORTS, exportReport } from '../demo/exports.js'
import { PRIORITY_MEANING, SOURCE_LABEL, STATUS_LABEL, VERDICT, sourceState } from '../demo/labels.js'
import FindingRow, { Priority } from './FindingRow.jsx'
import { AlertIcon, CheckIcon, DownloadIcon, Spinner } from './Icons.jsx'

const PAGE = 50

function Steps({ steps, scanning }) {
  return (
    <ol className="space-y-1 text-sm" aria-live="polite">
      {steps.map((s) => (
        <li key={s.id} className="flex items-center gap-2 text-slate-700 dark:text-slate-300">
          <CheckIcon className="size-4 text-emerald-600" /> {s.text}
        </li>
      ))}
      {scanning && (
        <li className="flex items-center gap-2 text-slate-500">
          <Spinner /> trabajando…
        </li>
      )}
    </ol>
  )
}

function Verdict({ report, meta }) {
  const v = VERDICT[report.verdict]
  return (
    <div className={`rounded-xl border p-4 ${v.style}`}>
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <p className="text-2xl font-semibold tracking-tight">
          Política: {v.title} <span className="font-mono text-base font-normal opacity-80">exit {report.exit_code}</span>
        </p>
        <p className="text-xs opacity-80">
          {meta.mode === 'snapshot' ? `Instantánea del ${meta.recordedAt}` : 'Datos en vivo'} · {meta.ms} ms
          {meta.simulateOutage && ' · caída de OSV simulada'}
        </p>
      </div>
      <p className="mt-1 text-sm">{v.text}</p>
      {report.policy.violations.length > 0 && (
        <details className="mt-2 text-sm">
          <summary className="cursor-pointer font-medium">{report.policy.violations.length} violación(es) de la política</summary>
          <ul className="mt-1 list-disc space-y-0.5 pl-5 font-mono text-xs">
            {report.policy.violations.slice(0, 30).map((x) => (
              <li key={x}>{x}</li>
            ))}
          </ul>
        </details>
      )}
      {report.policy.incomplete_reasons.map((r) => (
        <p key={r} className="mt-1 font-mono text-xs">
          ? {r}
        </p>
      ))}
      <p className="mt-3 rounded-md bg-black/5 px-2 py-1 font-mono text-xs dark:bg-white/5">
        $ depguard scan .{meta.mode === 'snapshot' ? ' --offline' : ''}
        <span className="text-slate-500"> # mismo motor, mismo veredicto → exit {report.exit_code}</span>
      </p>
    </div>
  )
}

function Counters({ summary, active, onPick }) {
  return (
    <div className="grid grid-cols-4 gap-2">
      {PRIORITIES.map((p) => (
        <button
          key={p}
          type="button"
          onClick={() => onPick(active === p ? 'all' : p)}
          aria-pressed={active === p}
          className={`card p-3 text-left transition-colors ${active === p ? 'ring-2 ring-accent-600' : 'hover:border-slate-300 dark:hover:border-slate-700'}`}
        >
          <Priority value={p} />
          <span className="mt-1 block text-2xl font-semibold text-slate-900 dark:text-white">{summary.by_priority[p]}</span>
          <span className="hidden text-xs text-slate-500 sm:block">{PRIORITY_MEANING[p]}</span>
        </button>
      ))}
    </div>
  )
}

function NotChecked({ components }) {
  const groups = ['error', 'unresolved', 'private']
    .map((status) => [status, components.filter((c) => c.status === status)])
    .filter(([, list]) => list.length)
  if (!groups.length) return null
  return (
    <section className="card p-4">
      <h3 className="flex items-center gap-2 font-medium text-amber-800 dark:text-amber-300">
        <AlertIcon /> Lo que no se pudo comprobar
      </h3>
      <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
        Estas dependencias no tienen veredicto. Un escáner que las mostrara como "seguras" estaría mintiendo.
      </p>
      {groups.map(([status, list]) => (
        <div key={status} className="mt-3">
          <p className="label">
            {STATUS_LABEL[status]} ({list.length})
          </p>
          <ul className="mt-1 space-y-0.5 font-mono text-xs">
            {list.slice(0, 12).map((c) => (
              <li key={`${c.purl}`}>
                {c.name}
                {c.version ? `@${c.version}` : ''}: <span className="text-slate-500">{c.unresolved_reason ?? c.error ?? status}</span>
              </li>
            ))}
            {list.length > 12 && <li className="text-slate-500">… y {list.length - 12} más</li>}
          </ul>
        </div>
      ))}
    </section>
  )
}

export default function Results({ phase, report, error, steps, meta, projectName, onNewScan }) {
  const [filter, setFilter] = useState('all')
  const [showIgnored, setShowIgnored] = useState(true)
  const [query, setQuery] = useState('')
  const [limit, setLimit] = useState(PAGE)
  const [exporting, setExporting] = useState(null)

  const visible = useMemo(() => {
    if (!report) return []
    const q = query.trim().toLowerCase()
    return report.findings.filter(
      (f) =>
        (filter === 'all' || f.priority === filter) &&
        (showIgnored || f.status !== 'ignored') &&
        (!q || f.package.name.toLowerCase().includes(q) || f.aliases.some((a) => a.toLowerCase().includes(q))),
    )
  }, [report, filter, showIgnored, query])

  if (phase === 'idle') {
    return (
      <div className="card flex min-h-80 flex-col items-center justify-center gap-3 p-8 text-center">
        <p className="font-medium text-slate-900 dark:text-white">Elige un ejemplo y pulsa «Escanear»</p>
        <p className="max-w-md text-sm text-slate-600 dark:text-slate-400">
          Verás el veredicto de la política, cada vulnerabilidad con su prioridad y el porqué, la remediación sugerida y lo
          que no se pudo comprobar. Puedes descargar el informe en JSON, SARIF o CycloneDX.
        </p>
      </div>
    )
  }
  if (phase === 'scanning') {
    return (
      <div className="card min-h-80 p-5">
        <Steps steps={steps} scanning />
      </div>
    )
  }
  if (phase === 'error') {
    return (
      <div role="alert" className="card border-red-300 p-5 dark:border-red-900">
        <p className="font-semibold text-red-800 dark:text-red-300">
          Error de la herramienta <span className="font-mono font-normal">exit {error.exitCode}</span>
        </p>
        <p className="mt-1 font-mono text-sm break-words">{error.message}</p>
        <p className="mt-2 text-sm text-slate-600 dark:text-slate-400">
          Igual que la CLI: un archivo no soportado o una configuración inválida detienen el escaneo en vez de dar un
          resultado engañoso.
        </p>
      </div>
    )
  }

  const s = report.summary
  const remediation = report.remediation.filter((r) => r.upgrade_to)
  return (
    <div className="flex flex-col gap-4">
      <Verdict report={report} meta={meta} />

      <div className="card flex flex-wrap gap-x-6 gap-y-2 p-4 text-sm">
        <span>
          <strong className="text-slate-900 dark:text-white">{s.components}</strong> dependencias ({s.direct} directas) en{' '}
          {s.manifests} archivo(s)
        </span>
        {Object.entries(report.sources).map(([k, v]) => {
          const st = sourceState(v)
          return (
            <span key={k} className="flex items-center gap-1" title={v}>
              {st.ok ? <CheckIcon className="size-3.5 text-emerald-600" /> : <AlertIcon className="size-3.5 text-amber-600" />}
              {SOURCE_LABEL[k]}: <span className="max-w-60 truncate text-slate-500">{st.text}</span>
            </span>
          )
        })}
      </div>

      <Counters summary={s} active={filter} onPick={setFilter} />

      {report.findings.length > 0 ? (
        <section className="card overflow-hidden" aria-label="Vulnerabilidades">
          <div className="flex flex-wrap items-center gap-3 border-b border-slate-200 p-3 dark:border-slate-800">
            <input
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filtrar por paquete o CVE"
              aria-label="Filtrar por paquete o CVE"
              className="min-w-0 flex-1 rounded-md border border-slate-300 bg-white px-2 py-1 text-sm dark:border-slate-700 dark:bg-slate-950"
            />
            {s.ignored > 0 && (
              <label className="flex items-center gap-1.5 text-sm text-slate-600 dark:text-slate-400">
                <input type="checkbox" checked={showIgnored} onChange={(e) => setShowIgnored(e.target.checked)} className="accent-accent-700" />
                mostrar ignoradas ({s.ignored})
              </label>
            )}
            <span className="text-xs text-slate-500">
              {visible.length} de {report.findings.length}
            </span>
          </div>
          <ul>
            {visible.slice(0, limit).map((f) => (
              <FindingRow key={`${f.id}|${f.package.purl}`} finding={f} />
            ))}
          </ul>
          {visible.length > limit && (
            <button type="button" className="btn-ghost w-full rounded-none py-3" onClick={() => setLimit((l) => l + PAGE)}>
              Mostrar {Math.min(PAGE, visible.length - limit)} más
            </button>
          )}
          {visible.length === 0 && <p className="p-4 text-sm text-slate-500">Ningún hallazgo con este filtro.</p>}
        </section>
      ) : (
        report.verdict !== 'INCOMPLETE' && (
          <p className="card p-4 text-sm text-emerald-800 dark:text-emerald-300">
            No hay vulnerabilidades conocidas para las versiones exactas analizadas.
          </p>
        )
      )}

      {remediation.length > 0 && (
        <section className="card p-4">
          <h3 className="font-medium text-slate-900 dark:text-white">Remediación sugerida</h3>
          <p className="text-sm text-slate-600 dark:text-slate-400">La actualización mínima por paquete que corrige sus hallazgos.</p>
          <ul className="mt-2 space-y-1 text-sm">
            {remediation.slice(0, 15).map((r) => (
              <li key={`${r.package}@${r.current}`} className="flex flex-wrap items-baseline gap-x-2">
                <Priority value={r.top_priority} />
                <span className="font-mono">
                  {r.package} {r.current} → <strong>{r.upgrade_to}</strong>
                </span>
                <span className="text-slate-500">
                  corrige {r.fixes} de {r.of}
                  {r.direct === false && r.via.length > 1 ? ` · llega vía ${r.via.slice(0, -1).join(' › ')}` : ''}
                </span>
              </li>
            ))}
          </ul>
        </section>
      )}

      <NotChecked components={report.components} />

      {report.problems.length > 0 && (
        <section className="card p-4">
          <h3 className="font-medium text-slate-900 dark:text-white">Avisos</h3>
          <ul className="mt-2 space-y-1 font-mono text-xs text-slate-600 dark:text-slate-400">
            {report.problems.map((p, i) => (
              <li key={`${p.code}-${i}`}>
                <span className="text-amber-700 dark:text-amber-400">{p.code}</span> {p.file ? `${p.file}: ` : ''}
                {p.message}
              </li>
            ))}
          </ul>
        </section>
      )}

      <section className="card flex flex-wrap items-center gap-2 p-4">
        <span className="mr-auto text-sm text-slate-600 dark:text-slate-400">Descargar el informe (se genera en tu navegador)</span>
        {EXPORTS.map((e) => (
          <button
            key={e.id}
            type="button"
            title={e.hint}
            className="btn-secondary py-1.5"
            disabled={exporting !== null}
            onClick={async () => {
              setExporting(e.id)
              try {
                await exportReport(e.id, report, projectName)
              } finally {
                setExporting(null)
              }
            }}
          >
            <DownloadIcon /> {e.label}
          </button>
        ))}
        {onNewScan && (
          <button type="button" className="btn-ghost py-1.5" onClick={onNewScan}>
            Nuevo escaneo
          </button>
        )}
      </section>
    </div>
  )
}
