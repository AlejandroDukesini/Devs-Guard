import { useId, useRef, useState } from 'react'
import { SAMPLES } from '../demo/samples.js'
import { MODES } from '../demo/useScanner.js'
import { readFiles } from '../demo/readFiles.js'
import { DEFAULT_CONFIG } from '../demo/labels.js'
import { ChevronIcon, Spinner, UploadIcon } from './Icons.jsx'

const PASTE_NAMES = ['requirements.txt', 'package-lock.json', 'package.json', 'poetry.lock', 'uv.lock', 'bom.cdx.json']
const EXPECT_STYLE = {
  PASS: 'text-emerald-700 dark:text-emerald-400',
  FAIL: 'text-red-700 dark:text-red-400',
  INCOMPLETE: 'text-amber-700 dark:text-amber-400',
}

function Segmented({ value, onChange, options, label }) {
  return (
    <div role="radiogroup" aria-label={label} className="grid grid-cols-2 gap-1 rounded-lg bg-slate-100 p-1 dark:bg-slate-800">
      {options.map(([id, text]) => (
        <button
          key={id}
          type="button"
          role="radio"
          aria-checked={value === id}
          onClick={() => onChange(id)}
          className={`rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
            value === id
              ? 'bg-white text-slate-900 shadow-sm dark:bg-slate-950 dark:text-white'
              : 'text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white'
          }`}
        >
          {text}
        </button>
      ))}
    </div>
  )
}

export default function ScanPanel({ scanning, onScan, onReset, state, setState }) {
  const { source, sampleId, userFiles, pasteName, pasteText, mode, configText, simulateOutage } = state
  const [dragging, setDragging] = useState(false)
  const [fileNotes, setFileNotes] = useState([])
  const [showAdvanced, setShowAdvanced] = useState(false)
  const fileInput = useRef(null)
  const ids = { paste: useId(), name: useId(), config: useId(), outage: useId() }
  const set = (patch) => setState((s) => ({ ...s, ...patch }))

  const takeFiles = async (list) => {
    const { files, skipped } = await readFiles(list, { singleFileAnyName: true })
    setFileNotes(files.length ? skipped : [...skipped, 'Ningún archivo soportado en la selección'])
    set({ userFiles: files, pasteText: '' })
  }

  const canScan =
    !scanning && (source === 'sample' ? Boolean(sampleId) : userFiles.length > 0 || pasteText.trim().length > 0)

  return (
    <form
      className="card flex flex-col gap-5 p-4 sm:p-5"
      onSubmit={(e) => {
        e.preventDefault()
        if (canScan) onScan()
      }}
    >
      <div>
        <p className="label mb-2">1 · Qué escanear</p>
        <Segmented
          label="Origen de los archivos"
          value={source}
          onChange={(v) => set({ source: v })}
          options={[
            ['sample', 'Ejemplos'],
            ['files', 'Tus archivos'],
          ]}
        />
      </div>

      {source === 'sample' ? (
        <fieldset className="flex flex-col gap-2">
          <legend className="sr-only">Proyecto de ejemplo</legend>
          {SAMPLES.map((s) => (
            <label
              key={s.id}
              className={`cursor-pointer rounded-lg border p-3 transition-colors ${
                sampleId === s.id
                  ? 'border-accent-600 bg-accent-50/60 dark:border-accent-500 dark:bg-accent-800/20'
                  : 'border-slate-200 hover:border-slate-300 dark:border-slate-800 dark:hover:border-slate-700'
              }`}
            >
              <input
                type="radio"
                name="sample"
                value={s.id}
                checked={sampleId === s.id}
                onChange={() => set({ sampleId: s.id })}
                className="sr-only"
              />
              <span className="flex items-baseline justify-between gap-2">
                <span className="font-medium text-slate-900 dark:text-white">{s.title}</span>
                <span className="shrink-0 font-mono text-xs text-slate-500">{s.format}</span>
              </span>
              <span className="mt-1 block text-sm text-slate-600 dark:text-slate-400">{s.blurb}</span>
              <span className={`mt-1 block font-mono text-xs ${EXPECT_STYLE[s.expect]}`}>esperado: {s.expect}</span>
            </label>
          ))}
        </fieldset>
      ) : (
        <div className="flex flex-col gap-3">
          <div
            onDragOver={(e) => {
              e.preventDefault()
              setDragging(true)
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={(e) => {
              e.preventDefault()
              setDragging(false)
              takeFiles(e.dataTransfer.files)
            }}
            className={`flex flex-col items-center gap-2 rounded-lg border-2 border-dashed p-5 text-center text-sm transition-colors ${
              dragging ? 'border-accent-600 bg-accent-50 dark:bg-accent-800/20' : 'border-slate-300 dark:border-slate-700'
            }`}
          >
            <UploadIcon className="size-6 text-slate-400" />
            <p className="text-slate-600 dark:text-slate-400">Arrastra lockfiles, manifests o un SBOM</p>
            <button type="button" className="btn-secondary py-1.5" onClick={() => fileInput.current?.click()}>
              Elegir archivos
            </button>
            <input
              ref={fileInput}
              type="file"
              multiple
              className="sr-only"
              tabIndex={-1}
              accept=".json,.txt,.lock,.toml"
              onChange={(e) => takeFiles(e.target.files)}
            />
          </div>
          {userFiles.length > 0 && (
            <ul className="space-y-1 font-mono text-xs text-slate-600 dark:text-slate-400" aria-label="Archivos seleccionados">
              {userFiles.map((f) => (
                <li key={f.path}>✓ {f.path}</li>
              ))}
            </ul>
          )}
          {fileNotes.map((n) => (
            <p key={n} className="text-xs text-amber-700 dark:text-amber-400">
              {n}
            </p>
          ))}
          <div className="relative text-center text-xs text-slate-400">
            <span className="bg-white px-2 dark:bg-slate-900">o pega el contenido</span>
          </div>
          <div className="flex items-center gap-2">
            <label htmlFor={ids.name} className="text-sm text-slate-600 dark:text-slate-400">
              Archivo
            </label>
            <select
              id={ids.name}
              value={pasteName}
              onChange={(e) => set({ pasteName: e.target.value })}
              className="rounded-md border border-slate-300 bg-white px-2 py-1 font-mono text-sm dark:border-slate-700 dark:bg-slate-950"
            >
              {PASTE_NAMES.map((n) => (
                <option key={n}>{n}</option>
              ))}
            </select>
          </div>
          <label htmlFor={ids.paste} className="sr-only">
            Contenido del archivo
          </label>
          <textarea
            id={ids.paste}
            value={pasteText}
            onChange={(e) => set({ pasteText: e.target.value, userFiles: [] })}
            rows={6}
            spellCheck={false}
            placeholder={'flask==2.2.2\nrequests==2.20.0'}
            className="w-full rounded-lg border border-slate-300 bg-white p-2 font-mono text-xs dark:border-slate-700 dark:bg-slate-950"
          />
          <p className="text-xs text-slate-500">
            Se procesa en tu navegador. Solo el ecosistema, el nombre y la versión de cada paquete se envían a OSV.dev; los
            CVE, a FIRST.
          </p>
        </div>
      )}

      <div>
        <p className="label mb-2">2 · Datos de vulnerabilidades</p>
        <Segmented
          label="Fuente de datos"
          value={mode}
          onChange={(v) => set({ mode: v })}
          options={Object.entries(MODES).map(([id, m]) => [id, m.label])}
        />
        <p className="mt-2 text-xs text-slate-500">{MODES[mode].hint}</p>
      </div>

      <div>
        <button
          type="button"
          className="flex w-full items-center gap-1 text-left label"
          aria-expanded={showAdvanced}
          onClick={() => setShowAdvanced((v) => !v)}
        >
          <ChevronIcon open={showAdvanced} className="size-3.5" /> 3 · Política y opciones
        </button>
        {showAdvanced && (
          <div className="mt-3 flex flex-col gap-3">
            <label htmlFor={ids.config} className="text-sm text-slate-600 dark:text-slate-400">
              <code className="font-mono">depguard.toml</code> (misma validación estricta que la CLI)
            </label>
            <textarea
              id={ids.config}
              value={configText}
              onChange={(e) => set({ configText: e.target.value })}
              rows={7}
              spellCheck={false}
              className="w-full rounded-lg border border-slate-300 bg-white p-2 font-mono text-xs dark:border-slate-700 dark:bg-slate-950"
            />
            {configText !== DEFAULT_CONFIG && (
              <button type="button" className="btn-ghost self-start text-xs" onClick={() => set({ configText: DEFAULT_CONFIG })}>
                Restaurar política por defecto
              </button>
            )}
            <label htmlFor={ids.outage} className="flex items-start gap-2 text-sm text-slate-600 dark:text-slate-400">
              <input
                id={ids.outage}
                type="checkbox"
                checked={simulateOutage}
                onChange={(e) => set({ simulateOutage: e.target.checked })}
                className="mt-1 accent-accent-700"
                disabled={mode === 'snapshot'}
              />
              <span>
                <strong className="font-medium">Simular caída de OSV.dev</strong> (respuestas 503). Sirve para ver que el
                resultado es INCOMPLETE y no un falso PASS.
              </span>
            </label>
          </div>
        )}
      </div>

      <div className="flex gap-2">
        <button type="submit" className="btn-primary flex-1" disabled={!canScan}>
          {scanning ? (
            <>
              <Spinner /> Escaneando…
            </>
          ) : (
            'Escanear'
          )}
        </button>
        <button type="button" className="btn-secondary" onClick={onReset}>
          Reiniciar
        </button>
      </div>
    </form>
  )
}
