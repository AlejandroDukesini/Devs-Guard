// Client of the local DepGuard API (dep_guard/server/app.py).
//
// The session token arrives once in the URL fragment (#token=...), which the
// browser never sends to any server. It is moved to sessionStorage (this tab
// only) and removed from the address bar. Every call sends it as an
// Authorization header; cookies are never used (credentials: 'omit').

const KEY = 'depguard.local.token'
const TOKEN_IN_HASH = /(?:^|[#&])token=([A-Za-z0-9_-]{20,128})(?:&|$)/

export function readToken() {
  const match = TOKEN_IN_HASH.exec(window.location.hash)
  if (match) {
    try {
      sessionStorage.setItem(KEY, match[1])
    } catch {
      // storage unavailable (private mode): the token lives only in memory
    }
    window.history.replaceState(null, '', window.location.pathname)
    return match[1]
  }
  try {
    return sessionStorage.getItem(KEY)
  } catch {
    return null
  }
}

/** Forget the token in this tab (after the session ends or expires). */
export function forgetToken() {
  try {
    sessionStorage.removeItem(KEY)
  } catch {
    // storage unavailable: nothing was stored
  }
}

export class ApiError extends Error {
  constructor(status, message) {
    super(message)
    this.status = status
  }
}

function filenameFrom(disposition, fallback) {
  const match = /filename="([A-Za-z0-9._-]+)"/.exec(disposition ?? '')
  return match ? match[1] : fallback
}

export function createApi(token) {
  async function call(method, path, body) {
    let response
    try {
      response = await fetch(path, {
        method,
        headers: {
          Authorization: `Bearer ${token}`,
          ...(body ? { 'Content-Type': 'application/json' } : {}),
        },
        body: body ? JSON.stringify(body) : undefined,
        credentials: 'omit',
        cache: 'no-store',
        redirect: 'error',
      })
    } catch {
      throw new ApiError(0, 'No se puede conectar con DepGuard. ¿Sigue abierto `depguard serve`?')
    }
    if (!response.ok) {
      let message = `HTTP ${response.status}`
      try {
        message = (await response.json()).error ?? message
      } catch {
        // non-JSON error body: keep the status line
      }
      throw new ApiError(response.status, message)
    }
    return response
  }

  const json = (method, path, body) => call(method, path, body).then((r) => r.json())

  return {
    info: () => json('GET', '/api/info'),
    browse: (path) => json('GET', path ? `/api/browse?path=${encodeURIComponent(path)}` : '/api/browse'),
    scan: (body) => json('POST', '/api/scans', body),
    history: () => json('GET', '/api/scans'),
    get: (id) => json('GET', `/api/scans/${encodeURIComponent(id)}`),
    remove: (id) => json('DELETE', `/api/scans/${encodeURIComponent(id)}`),
    endSession: () => json('POST', '/api/session/end', {}),
    async download(id, format) {
      const response = await call('GET', `/api/scans/${encodeURIComponent(id)}/export/${encodeURIComponent(format)}`)
      const blob = await response.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = filenameFrom(response.headers.get('content-disposition'), `depguard.${format}.json`)
      a.rel = 'noopener'
      document.body.appendChild(a)
      a.click()
      a.remove()
      setTimeout(() => URL.revokeObjectURL(url), 1000)
    },
  }
}
