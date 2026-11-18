import { useCallback, useEffect, useMemo, useState } from 'react'
import Results from '../components/Results.jsx'
import { Priority } from '../components/FindingRow.jsx'
import { ShieldIcon, Spinner, XIcon } from '../components/Icons.jsx'
import { VERDICT } from '../demo/labels.js'
import { createApi, forgetToken, readToken } from './api.js'

const EXPORTS = [
  { id: 'json', label: 'JSON', hint: 'depguard.report/v1, igual que la CLI' },
  { id: 'sarif', label: 'SARIF', hint: 'Para GitHub code scanning' },
  { id: 'cyclonedx', label: 'CycloneDX', hint: 'SBOM + vulnerabilidades (VEX)' },
  { id: 'spdx', label: 'SPDX', hint: 'SBOM SPDX 2.3' },
]

const OPTIONS = [
  ['latest', 'Última versión publicada', 'Consulta los registros oficiales (PyPI, npm, crates.io…) para distinguir actualizada de desactualizada'],
  ['nvd', 'NVD para CVSS/CWE', 'Solo para avisos sin vector CVSS; respeta el límite de la API de NVD'],
  ['epss', 'FIRST EPSS', 'Probabilidad de explotación'],
  ['kev', 'CISA KEV', 'Explotación activa confirmada'],
  ['offline', 'Sin conexión', 'Solo la caché local: lo no cacheado queda como INCOMPLETE'],
]

const baseName = (path) => (path ? path.split(/[\\/]/).filter(Boolean).pop() : '')
const when = (iso) => {
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString()
}

function FolderPicker({ api, onPick, disabled }) {
  const [listing, setListing] = useState(null)
  const [typed, setTyped] = useState('')
  const [error, setError] = useState(null)

  const open = useCallback(
    async (path) => {
      setError(null)
      try {
        const next = await api.browse(path)
        setListing(next)
        setTyped(next.path ?? '')
      } catch (err) {
        setError(err.message)
      }
    },
    [api],
  )

  useEffect(() => {
    // Initial listing (the allowed roots); state is only set once it arrives.
    let alive = true
    api
      .browse(null)
      .then((roots) => alive && setListing(roots))
      .catch((err) => alive && setError(err.message))
    return () => {
      alive = false
    }
  }, [api])

  const join = (dir) => (listing?.path ? `${listing.path}${listing.path.includes('\\') ? '\\' : '/'}${dir}` : dir)

  return (
    <section className="card p-4" aria-label="Proyecto a analizar">
      <h2 className="label">Proyecto</h2>
      <form
        className="mt-2 flex gap-2"
        onSubmit={(e) => {
          e.preventDefault()
          if (typed.trim()) open(typed.trim())
        }}
      >
        <input
          value={typed}
          onChange={(e) => setTyped(e.target.value)}
          placeholder="Ruta absoluta de la carpeta"
          aria-label="Ruta de la carpeta del proyecto"
          className="min-w-0 flex-1 rounded-md border border-slate-300 bg-white px-2 py-1 font-mono text-xs dark:border-slate-700 dark:bg-slate-950"
        />
        <button type="submit" className="btn-secondary px-3 py-1">
          Ir
        </button>
      </form>
      {error && (
        <p role="alert" className="mt-2 text-xs text-red-700 dark:text-red-400">
          {error}
        </p>
      )}
      {listing && (
        <>
          <ul className="mt-3 max-h-64 space-y-0.5 overflow-y-auto text-sm">
            {listing.parent && (
              <li>
                <button type="button" className="w-full rounded px-2 py-1 text-left hover:bg-slate-100 dark:hover:bg-slate-800" onClick={() => open(listing.parent)}>
                  ⬑ ..
                </button>
              </li>
            )}
            {listing.dirs.map((dir) => (
              <li key={dir}>
                <button
                  type="button"
                  className="w-full truncate rounded px-2 py-1 text-left font-mono text-xs hover:bg-slate-100 dark:hover:bg-slate-800"
                  title={join(dir)}
                  onClick={() => open(listing.path ? join(dir) : dir)}
                >
                  📁 {listing.path ? dir : dir}
                </button>
              </li>
            ))}
            {listing.path && listing.dirs.length === 0 && <li className="px-2 text-xs text-slate-500">Sin subcarpetas</li>}
          </ul>
          {listing.path && (
            <div className="mt-3">
              <p className="text-xs text-slate-500">
                {listing.files.length ? 'Archivos de dependencias aquí:' : 'No hay archivos de dependencias en esta carpeta (se buscarán en las subcarpetas).'}
              </p>
              <div className="mt-1 flex flex-wrap gap-1">
                {listing.files.map((f) => (
                  <span key={f} className="chip bg-slate-100 font-mono text-slate-700 dark:bg-slate-800 dark:text-slate-300">
                    {f}
                  </span>
                ))}
              </div>
              <button type="button" className="btn-primary mt-3 w-full" disabled={disabled} onClick={() => onPick(listing.path)}>
                Analizar {baseName(listing.path)}
              </button>
            </div>
          )}
        </>
      )}
    </section>
  )
}

function Options({ options, setOptions }) {
  return (
    <section className="card p-4" aria-label="Opciones del análisis">
      <h2 className="label">Opciones</h2>
      <div className="mt-2 space-y-2">
        {OPTIONS.map(([key, label, hint]) => (
          <label key={key} className="flex items-start gap-2 text-sm" title={hint}>
            <input
              type="checkbox"
              className="mt-0.5 accent-accent-700"
              checked={options[key]}
              onChange={(e) => setOptions((o) => ({ ...o, [key]: e.target.checked }))}
            />
            <span>
              {label}
              <span className="block text-xs text-slate-500">{hint}</span>
            </span>
          </label>
        ))}
        <label className="flex items-center justify-between gap-2 text-sm">
          Falla desde prioridad
          <select
            value={options.fail_on ?? ''}
            onChange={(e) => setOptions((o) => ({ ...o, fail_on: e.target.value || null }))}
            className="rounded-md border border-slate-300 bg-white px-2 py-1 text-sm dark:border-slate-700 dark:bg-slate-950"
          >
            <option value="">la del proyecto</option>
            {['P0', 'P1', 'P2', 'P3', 'none'].map((p) => (
              <option key={p} value={p}>
                {p === 'none' ? 'nunca' : p}
              </option>
            ))}
          </select>
        </label>
      </div>
    </section>
  )
}

function HistoryList({ items, current, onOpen, onDelete }) {
  if (!items.length) return null
  return (
    <section className="card p-4" aria-label="Historial de análisis">
      <h2 className="label">Historial</h2>
      <ul className="mt-2 space-y-1">
        {items.map((h) => (
          <li key={h.id} className={`flex items-center gap-2 rounded px-2 py-1 ${h.id === current ? 'bg-slate-100 dark:bg-slate-800' : ''}`}>
            <button type="button" className="min-w-0 flex-1 text-left" onClick={() => onOpen(h.id)} title={h.path}>
              <span className="flex items-center gap-2 text-sm">
                <span className={`chip border ${VERDICT[h.verdict]?.style ?? ''}`}>{h.verdict}</span>
                <span className="truncate font-medium">{baseName(h.path)}</span>
              </span>
              <span className="flex items-center gap-1 text-xs text-slate-500">
                {when(h.scanned_at)} · {h.components} deps
                {['P0', 'P1'].map((p) => (h.by_priority[p] ? <Priority key={p} value={p} /> : null))}
              </span>
            </button>
            <button type="button" className="btn-ghost p-1" aria-label={`Borrar análisis de ${baseName(h.path)}`} onClick={() => onDelete(h.id)}>
              <XIcon />
            </button>
          </li>
        ))}
      </ul>
    </section>
  )
}

export default function LocalApp() {
  const token = useMemo(() => readToken(), [])
  const api = useMemo(() => (token ? createApi(token) : null), [token])
  const [info, setInfo] = useState(null)
  const [fatal, setFatal] = useState(null)
  const [history, setHistory] = useState([])
  const [state, setState] = useState({ phase: 'idle' })
  const [options, setOptions] = useState({ latest: true, nvd: false, epss: true, kev: true, offline: false, fail_on: null })

  // Any 401 means the session ended or expired: stop and explain how to reopen.
  const fail = useCallback((err) => {
    if (err?.status === 401) {
      forgetToken()
      setFatal(`Sesión terminada (${err.message}).`)
      return true
    }
    return false
  }, [])

  const refresh = useCallback(
    () =>
      api
        ?.history()
        .then((h) => setHistory(h.scans))
        .catch(fail),
    [api, fail],
  )

  const endSession = async () => {
    await api.endSession().catch(() => null)
    forgetToken()
    setFatal('Sesión cerrada: el token ya no es válido.')
  }

  useEffect(() => {
    if (!api) return
    api
      .info()
      .then(setInfo)
      .then(refresh)
      .catch((err) => setFatal(err.message))
  }, [api, refresh])

  const run = async (path) => {
    const started = performance.now()
    setState({ phase: 'scanning', path, steps: [{ id: 'start', text: `Analizando ${path}` }] })
    try {
      const result = await api.scan({ path, ...options })
      setState({ phase: 'done', id: result.id, path, report: result.report, ms: Math.round(performance.now() - started) })
      refresh()
    } catch (err) {
      if (!fail(err)) setState({ phase: 'error', path, error: { exitCode: 2, message: err.message } })
    }
  }

  const open = async (id) => {
    try {
      const entry = await api.get(id)
      setState({ phase: 'done', id, path: entry.path, report: entry.report, ms: null })
    } catch (err) {
      if (!fail(err)) setState({ phase: 'error', error: { exitCode: 2, message: err.message } })
    }
  }

  const remove = async (id) => {
    await api.remove(id).catch(() => null)
    if (state.id === id) setState({ phase: 'idle' })
    refresh()
  }

  if (!api || fatal) {
    return (
      <main className="mx-auto max-w-xl p-8">
        <h1 className="flex items-center gap-2 text-xl font-semibold">
          <ShieldIcon /> DepGuard local
        </h1>
        <p role="alert" className="mt-4 text-sm">
          {fatal ?? 'Falta el token de sesión.'} Abre la interfaz con el enlace que imprime <code className="font-mono">depguard serve</code>.
        </p>
      </main>
    )
  }

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950">
      <header className="border-b border-slate-200 bg-white px-4 py-3 dark:border-slate-800 dark:bg-slate-900">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-x-4 gap-y-1">
          <h1 className="flex items-center gap-2 font-semibold text-slate-900 dark:text-white">
            <ShieldIcon className="size-5 text-accent-700" /> DepGuard local
          </h1>
          {info ? (
            <span className="text-xs text-slate-500">
              v{info.version} · solo esta máquina (127.0.0.1) · carpetas permitidas: <span className="font-mono">{info.roots.join(', ')}</span>
            </span>
          ) : (
            <Spinner />
          )}
          <button type="button" className="btn-ghost ml-auto py-1 text-xs" onClick={endSession}>
            Cerrar sesión
          </button>
        </div>
      </header>
      <div className="mx-auto grid max-w-7xl gap-4 p-4 lg:grid-cols-[20rem_minmax(0,1fr)]">
        <aside className="flex flex-col gap-4">
          <FolderPicker api={api} onPick={run} disabled={state.phase === 'scanning'} />
          <Options options={options} setOptions={setOptions} />
          <HistoryList items={history} current={state.id} onOpen={open} onDelete={remove} />
        </aside>
        <main className="min-w-0">
          {state.path && state.phase !== 'scanning' && (
            <p className="mb-2 truncate font-mono text-xs text-slate-500" title={state.path}>
              {state.path}
            </p>
          )}
          <Results
            phase={state.phase}
            report={state.report}
            error={state.error}
            steps={state.steps ?? []}
            meta={{ mode: 'live', ms: state.ms ?? '—' }}
            projectName={baseName(state.path)}
            exports={EXPORTS}
            onExport={(kind) => api.download(state.id, kind)}
            idleText="Elige la carpeta de tu proyecto y pulsa «Analizar». Solo se leen archivos de dependencias; no se ejecuta ni modifica nada."
          />
        </main>
      </div>
    </div>
  )
}
