// Scanner state for the demo UI. Runs the real engine (src/core) either
// against the live APIs or against the recorded snapshot (offline mode with
// a pre-filled cache). The "simulate outage" option wraps fetch so OSV
// answers 503: it exists to show the INCOMPLETE behaviour, and says so.

import { useCallback, useRef, useState } from 'react'
import { ToolError, scan } from '../core/engine.js'
import { Cache } from '../core/sources/cache.js'

export const MODES = {
  live: { label: 'En vivo', hint: 'Consulta OSV.dev, FIRST EPSS y CISA KEV ahora mismo.' },
  snapshot: { label: 'Instantánea', hint: 'Respuestas reales grabadas: sin red, solo para los ejemplos.' },
}

let snapshotPromise = null
export const loadSnapshot = () => (snapshotPromise ??= import('./snapshot.json').then((m) => m.default))

function outageFetch() {
  return async (url, init) => {
    if (new URL(url, globalThis.location?.href).hostname === 'api.osv.dev')
      return new Response('{"error":"simulated outage"}', { status: 503, headers: { 'Content-Type': 'application/json' } })
    return fetch(url, init)
  }
}

const IDLE = { phase: 'idle', report: null, error: null, steps: [], meta: null }

export function useScanner() {
  const [state, setState] = useState(IDLE)
  const runId = useRef(0)

  const run = useCallback(async ({ files, mode, configText, simulateOutage, source }) => {
    const id = ++runId.current
    const steps = []
    const push = (step) => {
      steps.push(step)
      if (runId.current === id) setState((s) => ({ ...s, steps: [...steps] }))
    }
    setState({ phase: 'scanning', report: null, error: null, steps: [], meta: null })
    const started = performance.now()
    try {
      const options = { configText, sleep: simulateOutage ? async () => {} : undefined }
      let recordedAt = null
      if (mode === 'snapshot') {
        const snapshot = await loadSnapshot()
        const cache = new Cache()
        cache.load(snapshot.cache)
        Object.assign(options, { offline: true, cache })
        recordedAt = snapshot.recorded_at
      } else if (simulateOutage) {
        options.fetchImpl = outageFetch()
      }
      push({ id: 'read', text: `${files.length} archivo(s) leídos en el navegador` })
      options.onProgress = (event, data) => {
        if (event === 'parsed') push({ id: 'parsed', text: `${data.components} dependencias descubiertas` })
        if (event === 'queried')
          push({ id: 'queried', text: mode === 'snapshot' ? 'Instantánea de OSV consultada' : 'OSV.dev consultado' })
      }
      const report = await scan(files, options)
      push({ id: 'risk', text: 'Riesgo y política evaluados' })
      if (runId.current !== id) return
      setState({
        phase: 'done',
        report,
        error: null,
        steps: [...steps],
        meta: { mode, recordedAt, simulateOutage, source, ms: Math.round(performance.now() - started) },
      })
    } catch (err) {
      if (runId.current !== id) return
      const toolError = err instanceof ToolError
      setState({
        phase: 'error',
        report: null,
        steps: [...steps],
        meta: { mode, source },
        error: toolError
          ? { exitCode: 2, message: err.message }
          : { exitCode: 2, message: `Error interno: ${err?.message ?? err}` },
      })
    }
  }, [])

  const reset = useCallback(() => {
    runId.current++
    setState(IDLE)
  }, [])

  return { ...state, run, reset }
}
