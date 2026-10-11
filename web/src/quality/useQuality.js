// State of the quality center: run history (verified on load), the run in
// progress and its errors. The suite itself is loaded on demand.

import { useCallback, useEffect, useState } from 'react'
import { HISTORY_KEY, loadHistory, saveRun } from './history.js'

const LOCK = 'depguard-quality-run'

/** Holds a cross-tab lock while `task` runs; null if another tab holds it. */
async function exclusive(task) {
  if (!globalThis.navigator?.locks) return task()
  return navigator.locks.request(LOCK, { ifAvailable: true }, (lock) => (lock ? task() : null))
}

export function useQuality() {
  const [history, setHistory] = useState({ reports: [], rejected: 0, loaded: false })
  const [run, setRun] = useState({ phase: 'idle', progress: null, error: null, persisted: true })

  const refresh = useCallback(async () => {
    const loaded = await loadHistory()
    setHistory({ ...loaded, loaded: true })
  }, [])

  useEffect(() => {
    // Initial load from storage (an external system), and results of runs in other tabs.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    refresh()
    const onStorage = (e) => e.key === HISTORY_KEY && refresh()
    window.addEventListener('storage', onStorage)
    return () => window.removeEventListener('storage', onStorage)
  }, [refresh])

  const start = useCallback(async () => {
    if (run.phase === 'running') return
    setRun({ phase: 'running', progress: { done: 0, total: 0, current: null }, error: null, persisted: true })
    try {
      const outcome = await exclusive(async () => {
        const { runQuality } = await import('./execute.js')
        const report = await runQuality({
          environment: 'browser',
          network: navigator.onLine !== false,
          production: import.meta.env.PROD,
          origin: location.origin,
          onProgress: (progress) => setRun((r) => ({ ...r, progress })),
        })
        return saveRun(report)
      })
      if (!outcome) throw new Error('Ya hay una ejecución en curso en otra pestaña.')
      setHistory({ reports: outcome.reports, rejected: 0, loaded: true })
      setRun({ phase: 'idle', progress: null, error: null, persisted: outcome.persisted })
    } catch (err) {
      setRun({ phase: 'error', progress: null, error: err?.message ?? String(err), persisted: true })
    }
  }, [run.phase])

  return { history, run, start }
}
