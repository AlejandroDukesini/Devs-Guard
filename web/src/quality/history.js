// Run history kept in this browser only (localStorage). Every entry is
// re-verified against its SHA-256 when loaded; edited or corrupted entries
// are dropped and reported, never shown as valid results.

import { verifyReport } from './report.js'

export const HISTORY_KEY = 'depguard.quality.history.v1'
export const MAX_RUNS = 10

/** localStorage wrapper that tolerates blocked storage (private mode, previews). */
export const browserStorage = {
  read(key) {
    try {
      return globalThis.localStorage?.getItem(key) ?? null
    } catch {
      return null
    }
  },
  write(key, value) {
    try {
      globalThis.localStorage?.setItem(key, value)
      return true
    } catch {
      return false
    }
  },
}

/** Plain in-memory storage with the same interface (used by the tests). */
export function memoryStorage() {
  const map = new Map()
  return { read: (k) => map.get(k) ?? null, write: (k, v) => (map.set(k, v), true) }
}

/** -> { reports (newest first), rejected: number } */
export async function loadHistory(storage = browserStorage) {
  const raw = storage.read(HISTORY_KEY)
  if (!raw) return { reports: [], rejected: 0 }
  let list
  try {
    list = JSON.parse(raw)
  } catch {
    return { reports: [], rejected: 1 }
  }
  if (!Array.isArray(list)) return { reports: [], rejected: 1 }
  const checks = await Promise.all(list.map((r) => verifyReport(r)))
  const reports = list.filter((_, i) => checks[i].valid)
  return { reports: reports.slice(0, MAX_RUNS), rejected: list.length - reports.length }
}

/** Prepends `report`; returns { reports, persisted }. */
export async function saveRun(report, storage = browserStorage) {
  const { reports } = await loadHistory(storage)
  const next = [report, ...reports.filter((r) => r.run_id !== report.run_id)].slice(0, MAX_RUNS)
  const persisted = storage.write(HISTORY_KEY, JSON.stringify(next))
  return { reports: next, persisted }
}
