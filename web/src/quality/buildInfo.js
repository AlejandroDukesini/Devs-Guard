// The build being served (see web/build-info.js). Absent only if the app is
// bundled without the Vite config, in which case versions cannot be compared.

/* global __BUILD_INFO__ */
export const BUILD =
  typeof __BUILD_INFO__ === 'undefined'
    ? { commit: null, dirty: null, fingerprint: null, files: 0, built_at: null }
    : __BUILD_INFO__
