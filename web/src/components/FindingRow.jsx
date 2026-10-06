import { useState } from 'react'
import { PRIORITY_MEANING, PRIORITY_STYLE, SEVERITY_STYLE } from '../demo/labels.js'
import { ChevronIcon, ExternalIcon } from './Icons.jsx'

// Only https links from advisories are rendered, always as plain anchors with
// rel="noopener noreferrer nofollow". Advisory text is rendered as text,
// never as HTML.
const safeHref = (url) => (typeof url === 'string' && url.startsWith('https://') ? url : null)

export function Priority({ value }) {
  return (
    <span className={`chip ${PRIORITY_STYLE[value]}`} title={PRIORITY_MEANING[value]}>
      {value}
    </span>
  )
}

function Origin({ pkg }) {
  const kind = pkg.direct === true ? 'directa' : pkg.direct === false ? 'transitiva' : 'origen desconocido'
  const scope = { prod: 'prod', dev: 'dev', unknown: '¿prod?' }[pkg.scope]
  const via = pkg.direct === false && pkg.paths[0]?.length > 1 ? pkg.paths[0].slice(0, -1).join(' › ') : null
  return (
    <span className="text-xs text-slate-600 dark:text-slate-400">
      {kind} · {scope}
      {via && <span className="block truncate font-mono text-slate-500" title={via}>vía {via}</span>}
    </span>
  )
}

export default function FindingRow({ finding: f }) {
  const [open, setOpen] = useState(false)
  const p = f.package
  const ignored = f.status === 'ignored'
  return (
    <li className={`border-b border-slate-200 last:border-0 dark:border-slate-800 ${ignored ? 'opacity-60' : ''}`}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="grid w-full grid-cols-[auto_1fr] items-start gap-x-3 gap-y-1 px-3 py-3 text-left hover:bg-slate-50 sm:grid-cols-[auto_minmax(0,1.1fr)_minmax(0,1.6fr)_auto_auto] sm:items-center dark:hover:bg-slate-800/40"
      >
        <span className="flex items-center gap-1.5 pt-0.5 sm:pt-0">
          <ChevronIcon open={open} className="size-3.5 text-slate-400" />
          <Priority value={f.priority} />
        </span>
        <span className="min-w-0">
          <span className="block truncate font-medium text-slate-900 dark:text-white" title={p.name}>
            {p.name}
          </span>
          <span className="block font-mono text-xs text-slate-500">
            {p.version} · {p.ecosystem}
          </span>
        </span>
        <span className="col-start-2 min-w-0 sm:col-start-auto">
          <span className="flex flex-wrap items-center gap-1.5">
            <span className="font-mono text-sm text-slate-800 dark:text-slate-200">{f.id}</span>
            {f.kev && <span className="chip bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300">KEV</span>}
            {ignored && <span className="chip bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300">ignorada</span>}
          </span>
          <span className="block truncate text-sm text-slate-600 dark:text-slate-400" title={f.summary}>
            {f.summary}
          </span>
        </span>
        <span className="col-start-2 flex gap-3 text-sm sm:col-start-auto sm:block sm:text-right">
          <span className={`font-medium ${SEVERITY_STYLE[f.severity]}`}>
            {f.severity}
            {f.cvss.score !== null && <span className="ml-1 font-mono text-xs text-slate-500">{f.cvss.score.toFixed(1)}</span>}
          </span>
          <span className="block font-mono text-xs text-slate-500">
            {f.fixed_versions.length ? `→ ${f.fixed_versions[0]}` : 'sin fix'}
          </span>
        </span>
        <span className="col-start-2 sm:col-start-auto sm:w-36">
          <Origin pkg={p} />
        </span>
      </button>

      {open && (
        <div className="grid gap-4 bg-slate-50 px-4 py-4 text-sm sm:grid-cols-2 dark:bg-slate-900/60">
          <div className="sm:col-span-2">
            <p className="label mb-1">Por qué es {f.priority} ({PRIORITY_MEANING[f.priority].toLowerCase()})</p>
            <ul className="space-y-0.5">
              {f.reasons.map((r) => (
                <li key={r.code} className="flex flex-col sm:flex-row sm:gap-3">
                  <code className="shrink-0 font-mono text-xs text-slate-500 sm:w-36">{r.code}</code>
                  <span>{r.text}</span>
                </li>
              ))}
            </ul>
          </div>
          {ignored && (
            <div className="sm:col-span-2">
              <p className="label mb-1">Excepción aplicada</p>
              <p>
                {f.ignore.reason} <span className="text-slate-500">(caduca {f.ignore.expires})</span>
              </p>
            </div>
          )}
          <div>
            <p className="label mb-1">Qué hacer</p>
            <p>
              {f.fixed_versions.length
                ? `Actualizar ${p.name} a ${f.fixed_versions[0]} o superior${p.direct === false ? ' (actualizando la dependencia que lo trae, o con overrides/resolutions)' : ''}.`
                : 'No hay versión corregida publicada: valora mitigar, sustituir el paquete o documentar una excepción con caducidad.'}
            </p>
          </div>
          <div>
            <p className="label mb-1">Dónde</p>
            <p className="font-mono text-xs break-all">
              {p.locations.map((l) => `${l.file}${l.line ? `:${l.line}` : ''}`).join(', ')}
            </p>
            {p.paths[0] && <p className="mt-1 font-mono text-xs break-all text-slate-500">{p.paths[0].join(' › ')}</p>}
          </div>
          <div>
            <p className="label mb-1">Identificadores</p>
            <p className="font-mono text-xs break-all">{f.aliases.join(', ')}</p>
            {f.cwes.length > 0 && <p className="mt-1 font-mono text-xs text-slate-500">{f.cwes.join(', ')}</p>}
            {f.cvss.vector && <p className="mt-1 font-mono text-xs break-all text-slate-500">{f.cvss.vector}</p>}
          </div>
          <div>
            <p className="label mb-1">Referencias</p>
            <ul className="space-y-1">
              {[`https://osv.dev/vulnerability/${encodeURIComponent(f.id)}`, ...f.references]
                .map(safeHref)
                .filter(Boolean)
                .slice(0, 4)
                .map((url) => (
                  <li key={url} className="min-w-0">
                    <a
                      href={url}
                      target="_blank"
                      rel="noopener noreferrer nofollow"
                      className="inline-flex max-w-full items-center gap-1 text-accent-700 hover:underline dark:text-accent-500"
                    >
                      <span className="truncate">{url.replace(/^https:\/\//, '')}</span>
                      <ExternalIcon />
                    </a>
                  </li>
                ))}
            </ul>
          </div>
        </div>
      )}
    </li>
  )
}
