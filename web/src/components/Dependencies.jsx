import { useMemo, useState } from 'react'
import { PATCH_LABEL, PATCH_ORDER, PATCH_STYLE } from '../demo/labels.js'

const PAGE = 50

// Every dependency with its remediation state (report field `patch_status`).
// Text from the report is rendered as text, never as HTML.
export default function Dependencies({ components, counts }) {
  const [state, setState] = useState('all')
  const [query, setQuery] = useState('')
  const [limit, setLimit] = useState(PAGE)

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase()
    return components
      .filter((c) => (state === 'all' || c.patch_status === state) && (!q || c.name.toLowerCase().includes(q)))
      .sort((a, b) => PATCH_ORDER.indexOf(a.patch_status) - PATCH_ORDER.indexOf(b.patch_status) || a.name.localeCompare(b.name))
  }, [components, state, query])

  if (!components.length) return null
  return (
    <section className="card overflow-hidden" aria-label="Dependencias y estado de parches">
      <div className="border-b border-slate-200 p-3 dark:border-slate-800">
        <h3 className="font-medium text-slate-900 dark:text-white">Dependencias y estado de parches</h3>
        <div className="mt-2 flex flex-wrap gap-1.5" role="group" aria-label="Filtrar por estado">
          <button
            type="button"
            aria-pressed={state === 'all'}
            onClick={() => setState('all')}
            className={`chip border ${state === 'all' ? 'border-accent-600 ring-1 ring-accent-600' : 'border-slate-300 dark:border-slate-700'}`}
          >
            todas ({components.length})
          </button>
          {PATCH_ORDER.filter((s) => counts?.[s]).map((s) => (
            <button
              key={s}
              type="button"
              aria-pressed={state === s}
              onClick={() => setState(state === s ? 'all' : s)}
              className={`chip ${PATCH_STYLE[s]} ${state === s ? 'ring-2 ring-accent-600' : ''}`}
            >
              {PATCH_LABEL[s]} ({counts[s]})
            </button>
          ))}
        </div>
        <input
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Filtrar por paquete"
          aria-label="Filtrar dependencias por paquete"
          className="mt-2 w-full rounded-md border border-slate-300 bg-white px-2 py-1 text-sm dark:border-slate-700 dark:bg-slate-950"
        />
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead className="label">
            <tr>
              <th className="px-3 py-2 font-semibold">Paquete</th>
              <th className="px-3 py-2 font-semibold">Instalada</th>
              <th className="px-3 py-2 font-semibold">Última estable</th>
              <th className="px-3 py-2 font-semibold">Estado</th>
              <th className="px-3 py-2 font-semibold">Detalle</th>
            </tr>
          </thead>
          <tbody>
            {visible.slice(0, limit).map((c) => (
              <tr key={`${c.purl}|${c.locations[0]?.file ?? ''}`} className="border-t border-slate-200 align-top dark:border-slate-800">
                <td className="px-3 py-2">
                  <span className="font-mono break-all">{c.name}</span>
                  <span className="block text-xs text-slate-500">
                    {c.ecosystem} · {c.direct === true ? 'directa' : c.direct === false ? 'transitiva' : '¿directa?'} · {c.scope}
                  </span>
                </td>
                <td className="px-3 py-2 font-mono">{c.version ?? '—'}</td>
                <td className="px-3 py-2 font-mono">
                  {c.latest ?? '—'}
                  {c.latest_vulnerable === true && (
                    <span className="block text-xs text-red-700 dark:text-red-400">con avisos conocidos</span>
                  )}
                </td>
                <td className="px-3 py-2">
                  <span className={`chip ${PATCH_STYLE[c.patch_status]}`}>{PATCH_LABEL[c.patch_status]}</span>
                </td>
                <td className="px-3 py-2 text-xs text-slate-600 dark:text-slate-400">{c.patch_note}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {visible.length > limit && (
        <button type="button" className="btn-ghost w-full rounded-none py-3" onClick={() => setLimit((l) => l + PAGE)}>
          Mostrar {Math.min(PAGE, visible.length - limit)} más
        </button>
      )}
      {visible.length === 0 && <p className="p-4 text-sm text-slate-500">Ninguna dependencia con este filtro.</p>}
    </section>
  )
}
