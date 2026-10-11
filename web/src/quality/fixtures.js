// The repository's shared fixtures (../fixtures), bundled into the quality
// chunk so the suite runs on the very same inputs and goldens as pytest and
// vitest. This module is only loaded when a quality run starts.

import { createMockFetch } from './mockSources.js'
import webLockfile from '../../package-lock.json?raw'
import webManifest from '../../package.json?raw'
import { netlifyToml } from 'virtual:repo-files'

const RAW = import.meta.glob('../../../fixtures/**/*.{json,txt,lock,toml}', {
  query: '?raw',
  import: 'default',
  eager: true,
})
const PREFIX = '../../../fixtures/'
const FILES = new Map(Object.entries(RAW).map(([path, text]) => [path.slice(PREFIX.length), text]))

export function readText(rel) {
  const text = FILES.get(rel)
  if (text === undefined) throw new Error(`fixture not bundled: ${rel}`)
  return text
}
export const readJson = (rel) => JSON.parse(readText(rel))

/** All files of a fixture project as [{path, content}], sorted. */
export function projectFiles(project) {
  const prefix = `projects/${project}/`
  return [...FILES]
    .filter(([path]) => path.startsWith(prefix))
    .map(([path, content]) => ({ path: path.slice(prefix.length), content }))
    .sort((a, b) => (a.path < b.path ? -1 : 1))
}

export const fixtureMockFetch = () =>
  createMockFetch({
    index: readJson('osv-mock/index.json'),
    epss: readJson('osv-mock/epss.json'),
    kev: readJson('osv-mock/kev.json'),
    vuln: (id) => FILES.get(`osv-mock/vulns/${id}.json`) ?? null,
  })

/** Deployment and dependency files evaluated by the suite. */
export const PROJECT_FILES = { webLockfile, webManifest, netlifyToml }
