// The quality suite: real checks run against the real engine (src/core), the
// shared fixtures and the project's deployment/dependency files. The same
// definitions run in the browser ("Centro de seguridad y calidad") and in
// vitest (tests/quality.test.jsx), so CI and the web report on one suite.
//
// Each test returns its evidence (string or [string]); check() records a
// failure, skip() records that it could not be executed here.

import { createElement } from 'react'
import { flushSync } from 'react-dom'
import { createRoot } from 'react-dom/client'
import { parse as parseToml } from 'smol-toml'
import { compare } from '../core/versions.js'
import { baseScoreV3 } from '../core/cvss.js'
import { assess } from '../core/risk.js'
import { makeFinding } from '../core/correlate.js'
import { makeComponent } from '../core/models.js'
import { ToolError, scan } from '../core/engine.js'
import { Cache } from '../core/sources/cache.js'
import { ALLOWED_HOSTS, HttpClient, SourceError } from '../core/sources/http.js'
import { DiscoveryError, MAX_FILES, MAX_FILE_BYTES, discover } from '../core/discovery.js'
import { clean } from '../core/textutil.js'
import { ConfigError, parseConfigText } from '../core/config.js'
import { toSarif } from '../core/reporters/sarif.js'
import { toCycloneDx } from '../core/reporters/cyclonedx.js'
import { parseRequirement } from '../core/adapters/requirements.js'
import { SECURITY_HEADERS } from '../../security-headers.js'
import { SAMPLES, loadSample } from '../demo/samples.js'
import { loadSnapshot } from '../demo/useScanner.js'
import FindingRow from '../components/FindingRow.jsx'
import { FIXTURE_TODAY, mockScanOptions, normalise } from './mockSources.js'
import { PROJECT_FILES, fixtureMockFetch, projectFiles, readJson, readText } from './fixtures.js'
import { buildReport, canonicalJson, sha256Hex, verifyReport } from './report.js'
import { loadHistory, memoryStorage, saveRun } from './history.js'
import { check, skip } from './runner.js'

// Budgets are generous on purpose: they catch pathological slowdowns, not
// differences between machines.
export const PERF_BUDGET = Object.freeze({
  sampleScanMs: 2000,
  versionCompares: 20_000,
  versionCompareMs: 750,
  discoveryMs: 500,
})
export const APPROVED_RUNTIME_DEPS = ['react', 'react-dom', 'smol-toml']
export const NPM_REGISTRY = 'https://registry.npmjs.org/'

const fixtureScan = (project, extra = {}) => scan(projectFiles(project), mockScanOptions(fixtureMockFetch(), extra))
const sameJson = (a, b) => canonicalJson(a) === canonicalJson(b)
const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`

async function rejects(promiseOrFn, ErrorType, contains = '') {
  try {
    await (typeof promiseOrFn === 'function' ? promiseOrFn() : promiseOrFn)
  } catch (err) {
    return err instanceof ErrorType && String(err.message).includes(contains) ? err : null
  }
  return null
}

async function snapshotScan(files, snapshot, fetchImpl) {
  const cache = new Cache()
  cache.load(snapshot.cache)
  return scan(files, { offline: true, cache, today: snapshot.recorded_at, fetchImpl })
}

const median = (xs) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)]

// Same cases as tests/regen_golden.py::CASES
const GOLDEN_CASES = [
  ['npm-app', 'npm-app', null, 'lockfile npm con dependencias transitivas'],
  ['npm-app-policy', 'npm-app', 'configs/npm-app-policy.toml', 'política personalizada con excepciones'],
  ['npm-no-lock', 'npm-no-lock', null, 'package.json sin lockfile (rangos sin resolver)'],
  ['py-uv', 'py-uv', null, 'uv.lock'],
  ['py-poetry', 'py-poetry', null, 'poetry.lock'],
  ['py-requirements', 'py-requirements', null, 'requirements.txt de producción y desarrollo'],
  ['sbom', 'sbom', null, 'SBOM CycloneDX con Maven y Go'],
  ['malformed', 'malformed', null, 'lockfile corrupto'],
]

const unit = [
  {
    id: 'UNI-001',
    name: 'Comparación de versiones',
    description: 'Ordena versiones npm, PyPI, Maven y Go igual que el motor Python (tabla golden compartida), en ambos sentidos.',
    category: 'unit',
    severity: 'high',
    recommendation: 'Revisar src/core/versions.js frente a dep_guard/versions.py y regenerar los golden con Python.',
    run() {
      const cases = readJson('golden/versions.json').cases
      const bad = []
      for (const [eco, a, b, expected] of cases) {
        if (compare(eco, a, b) !== expected) bad.push(`${eco}: ${a} vs ${b}`)
        else if (expected !== null && compare(eco, b, a) !== (-expected || 0)) bad.push(`${eco}: ${b} vs ${a} (inverso)`)
      }
      check(!bad.length, `${bad.length} discrepancia(s): ${bad.slice(0, 5).join('; ')}`)
      return `${cases.length} casos golden, 0 discrepancias`
    },
  },
  {
    id: 'UNI-002',
    name: 'Puntuación CVSS v3',
    description: 'Calcula la puntuación base CVSS v3.x de cada vector de la tabla golden.',
    category: 'unit',
    severity: 'high',
    recommendation: 'Revisar src/core/cvss.js (redondeo roundup de la especificación CVSS 3.1).',
    run() {
      const cases = readJson('golden/cvss.json').cases
      const bad = cases.filter(([vector, score]) => baseScoreV3(vector) !== score)
      check(!bad.length, `${bad.length} vector(es) con puntuación distinta: ${bad.slice(0, 3).map(([v]) => v).join('; ')}`)
      return `${cases.length} vectores, 0 discrepancias`
    },
  },
  {
    id: 'UNI-003',
    name: 'Tabla de decisión de prioridad P0–P3',
    description: 'Asigna la prioridad y los motivos esperados combinando severidad, EPSS, KEV, ámbito y origen.',
    category: 'unit',
    severity: 'critical',
    recommendation: 'Revisar src/core/risk.js frente a docs/risk-model.md; una prioridad errónea oculta riesgos reales.',
    run() {
      const cases = readJson('golden/risk.json').cases
      const bad = []
      for (const c of cases) {
        const i = c.in
        const component = makeComponent({
          ecosystem: 'npm',
          name: 'pkg',
          version: '1.0.0',
          purl: 'pkg:npm/pkg',
          direct: i.direct,
          scope: i.scope,
          paths: i.path ? [i.path] : [],
        })
        const finding = makeFinding(component, {
          id: 'X',
          aliases: i.cves ? ['CVE-2099-0001'] : ['GHSA-x'],
          summary: 's',
          severity: i.severity,
          cvssScore: i.cvss,
          fixedVersions: i.fix ? [i.fix] : [],
        })
        finding.epss = i.epss
        finding.epssPercentile = i.epss !== null ? 0.5 : null
        finding.kev = i.kev
        assess(finding)
        if (finding.priority !== c.priority || !sameJson(finding.reasons.map((r) => r.code), c.reasons))
          bad.push(`${c.name}: ${finding.priority} en vez de ${c.priority}`)
      }
      check(!bad.length, bad.join('; '))
      return `${cases.length} escenarios de riesgo con prioridad y motivos esperados`
    },
  },
  {
    id: 'UNI-004',
    name: 'Parser de requisitos PEP 508',
    description: 'Interpreta especificadores válidos y rechaza líneas malformadas en requirements.txt.',
    category: 'unit',
    severity: 'medium',
    recommendation: 'Revisar parseRequirement en src/core/adapters/requirements.js.',
    run() {
      const valid = [
        ['requests==2.0', [{ op: '==', version: '2.0' }]],
        ['uvicorn[standard]==0.30.0 ; python_version>"3"', [{ op: '==', version: '0.30.0' }]],
        ['pkg (>=1.0, <2)', [{ op: '>=', version: '1.0' }, { op: '<', version: '2' }]],
      ]
      const invalid = ['this is not a requirement !!', 'pkg==', 'pkg[unclosed==1', '==1.0']
      for (const [text, specs] of valid) check(sameJson(parseRequirement(text)?.specs, specs), `mal interpretado: ${text}`)
      for (const text of invalid) check(parseRequirement(text) === null, `aceptada línea inválida: ${text}`)
      return `${valid.length} válidas interpretadas, ${invalid.length} inválidas rechazadas`
    },
  },
  {
    id: 'UNI-005',
    name: 'Neutralización de caracteres peligrosos',
    description: 'Elimina caracteres de control, ANSI, bidi (Trojan Source) y de ancho cero del texto de terceros.',
    category: 'unit',
    severity: 'high',
    recommendation: 'Revisar UNSAFE_RANGES en src/core/textutil.js.',
    run() {
      const hostile = 'ok' + String.fromCharCode(0x1b) + '[31mred' + String.fromCharCode(0x07, 0x202e) + 'hid' + String.fromCharCode(0x200b) + 'den'
      const out = clean(hostile)
      check(out === 'ok[31mredhidden', `resultado inesperado (${out.length} caracteres)`)
      check(Array.from(clean('x'.repeat(900))).length === 500, 'no se aplica la longitud máxima')
      return ['ESC, BEL, U+202E y U+200B eliminados', 'longitud limitada a 500 caracteres']
    },
  },
  {
    id: 'UNI-006',
    name: 'Validación estricta de la configuración',
    description: 'Rechaza claves y secciones desconocidas, tipos erróneos y excepciones permanentes o sin motivo.',
    category: 'unit',
    severity: 'high',
    recommendation: 'Revisar src/core/config.js: una clave mal escrita nunca debe desactivar en silencio una regla.',
    run() {
      const cases = [
        ['[policy]\nfail_on_kevv = true', 'unknown key'],
        ['[polcy]\n', 'unknown section'],
        ['[policy]\nfail_on_kev = "yes"', 'wrong type'],
        ['[[ignore]]\nid = "CVE-1"\nreason = "long enough reason"\nexpires = 2150-01-01', 'permanent ignores'],
        ['[[ignore]]\nid = "CVE-1"\nreason = "short"\nexpires = 2099-02-01', 'reason'],
        ['[[ignore]]\nreason = "long enough reason"\nexpires = 2099-02-01', 'id'],
      ]
      for (const [text, message] of cases) {
        let err = null
        try {
          parseConfigText(text, FIXTURE_TODAY)
        } catch (e) {
          err = e
        }
        check(err instanceof ConfigError && err.message.includes(message), `aceptada: ${text.split('\n').join(' ')}`)
      }
      return `${cases.length} configuraciones inválidas rechazadas con ConfigError`
    },
  },
]

const integration = GOLDEN_CASES.map(([name, project, config, label], i) => ({
  id: `INT-${String(i + 1).padStart(3, '0')}`,
  name: `Informe completo: ${name}`,
  description: `Escaneo de extremo a extremo (${label}) con fuentes simuladas; el informe debe ser idéntico al del motor Python.`,
  category: 'integration',
  severity: 'critical',
  recommendation: 'Comparar el informe con fixtures/golden y corregir el motor que diverge (regenerar los golden solo desde Python).',
  async run() {
    const report = await fixtureScan(project, config ? { configText: readText(config), configSource: config } : {})
    const expected = readJson(`golden/report-${name}.json`)
    const actual = normalise(report)
    const differing = Object.keys({ ...expected, ...actual }).filter((k) => !sameJson(actual[k], expected[k]))
    check(!differing.length, `campos distintos de la referencia: ${differing.join(', ')}`)
    return [
      `veredicto ${report.verdict} (exit ${report.exit_code}), igual a la referencia`,
      `${plural(report.summary.components, 'componente', 'componentes')}, ${plural(report.summary.findings, 'hallazgo', 'hallazgos')}`,
    ]
  },
}))

const functional = [
  {
    id: 'FUN-001',
    name: 'Modo instantánea sin red',
    description: 'Con la instantánea grabada, un escaneo completo no realiza ninguna petición de red.',
    category: 'functional',
    severity: 'high',
    recommendation: 'Revisar el modo offline del motor (engine.js) y la carga de la caché.',
    async run() {
      const snapshot = await loadSnapshot()
      let requests = 0
      const report = await snapshotScan(await loadSample('express-shop'), snapshot, async () => {
        requests++
        throw new Error('network blocked')
      })
      check(requests === 0, `${requests} petición(es) de red en modo instantánea`)
      check(report.sources.osv === 'offline-cache', `fuente OSV: ${report.sources.osv}`)
      return [`0 peticiones de red`, `${report.summary.components} componentes analizados desde la caché`]
    },
  },
  {
    id: 'FUN-002',
    name: 'Paquetes privados no se envían a OSV',
    description: 'Los nombres que coinciden con private_packages nunca salen del navegador.',
    category: 'functional',
    severity: 'critical',
    recommendation: 'Revisar markPrivate en engine.js y el filtrado de consultas en sources/osv.js.',
    async run() {
      const mock = fixtureMockFetch()
      const files = [{ path: 'requirements.txt', content: 'acme-crypto==41.0.0\ninternal-billing==1.0\n' }]
      const report = await scan(files, mockScanOptions(mock, { configText: '[sources]\nprivate_packages = ["internal-*"]\n' }))
      const sent = mock.state.bodies.join('')
      check(!sent.includes('internal-billing'), 'el nombre privado aparece en la consulta a OSV')
      check(report.components.find((c) => c.name === 'internal-billing')?.status === 'private', 'el componente no figura como privado')
      return [`${mock.state.calls.batch} consulta(s) a OSV sin el paquete privado`, 'internal-billing marcado como private']
    },
  },
  {
    id: 'FUN-003',
    name: 'Excepciones con caducidad',
    description: 'Una excepción documentada suprime su hallazgo y queda reflejada como supresión en SARIF.',
    category: 'functional',
    severity: 'medium',
    recommendation: 'Revisar applyIgnores en policy.js y las suppressions en reporters/sarif.js.',
    async run() {
      const report = await fixtureScan('npm-app', {
        configText: '[[ignore]]\nid = "CVE-2099-1003"\nreason = "documented reason here"\nexpires = 2099-06-30',
      })
      const ignored = report.findings.filter((f) => f.status === 'ignored')
      check(ignored.length === 1, `${ignored.length} hallazgos ignorados (se esperaba 1)`)
      const run = (await toSarif(report)).runs[0]
      const suppressed = run.results.filter((r) => r.suppressions).length
      check(suppressed === 1, `${suppressed} supresiones en SARIF`)
      return [`${ignored[0].id} ignorado hasta ${ignored[0].ignore.expires}`, '1 supresión en SARIF']
    },
  },
  {
    id: 'FUN-004',
    name: 'Exportación CycloneDX reutilizable',
    description: 'El SBOM exportado se puede volver a escanear y produce exactamente los mismos hallazgos.',
    category: 'functional',
    severity: 'medium',
    recommendation: 'Revisar reporters/cyclonedx.js y el adaptador cyclonedx.js.',
    async run() {
      const report = await fixtureScan('npm-app')
      const bom = toCycloneDx(report, 'demo-shop')
      check(bom.specVersion === '1.6', `specVersion ${bom.specVersion}`)
      const again = await scan([{ path: 'bom.cdx.json', content: JSON.stringify(bom) }], mockScanOptions(fixtureMockFetch()))
      const key = (f) => `${f.id}|${f.package.name}|${f.package.version}`
      check(sameJson(again.findings.map(key).sort(), report.findings.map(key).sort()), 'los hallazgos cambian tras el reescaneo')
      return `CycloneDX 1.6 con ${bom.components.length} componentes; ${again.findings.length} hallazgos idénticos al reescanear`
    },
  },
  {
    id: 'FUN-005',
    name: 'Texto de avisos mostrado como texto',
    description: 'Un aviso con HTML y enlaces javascript: o http: se muestra sin crear elementos ni enlaces inseguros.',
    category: 'functional',
    severity: 'critical',
    recommendation: 'Renderizar el texto de terceros solo como texto y filtrar enlaces que no sean https:// (FindingRow.jsx).',
    async run() {
      if (typeof document === 'undefined') skip('no hay DOM en este entorno')
      const report = await fixtureScan('npm-app')
      const finding = {
        ...report.findings[0],
        summary: '<img src=x onerror="window.__xss=1"><script>window.__xss=1</script>',
        references: ['javascript:window.__xss=1', 'http://insecure.example/advisory', 'https://example.org/ok'],
      }
      const host = document.createElement('ul')
      const root = createRoot(host)
      try {
        flushSync(() => root.render(createElement(FindingRow, { finding })))
        host.querySelector('button').click()
        await new Promise((resolve) => setTimeout(resolve, 0))
        flushSync(() => {})
        check(!host.querySelector('img, script'), 'el resumen se interpretó como HTML')
        check(host.textContent.includes('<img src=x'), 'el resumen no aparece como texto')
        const hrefs = [...host.querySelectorAll('a')].map((a) => a.getAttribute('href'))
        check(hrefs.length > 0, 'no se mostró ninguna referencia')
        check(hrefs.every((h) => h.startsWith('https://')), `enlace inseguro: ${hrefs.find((h) => !h.startsWith('https://'))}`)
        check(globalThis.window?.__xss === undefined, 'se ejecutó código del aviso')
        return [`0 elementos img/script creados`, `${hrefs.length} enlaces, todos https://`]
      } finally {
        root.unmount()
      }
    },
  },
  {
    id: 'FUN-006',
    name: 'Cabeceras de seguridad servidas',
    description: 'La página publicada se sirve con la CSP y las cabeceras de seguridad definidas en el repositorio.',
    category: 'functional',
    severity: 'high',
    recommendation: 'Comprobar que netlify.toml (o el servidor) aplica security-headers.js a todas las rutas.',
    async run(ctx) {
      if (ctx.env !== 'browser' || !ctx.production) skip('solo verificable en la build de producción servida')
      const res = await fetch(`${ctx.origin}/`, { cache: 'no-store' })
      const missing = Object.entries(SECURITY_HEADERS).filter(([k, v]) => res.headers.get(k) !== v)
      check(!missing.length, `cabeceras ausentes o distintas: ${missing.map(([k]) => k).join(', ')}`)
      return `${Object.keys(SECURITY_HEADERS).length} cabeceras presentes con el valor esperado`
    },
  },
]

const negative = [
  {
    id: 'NEG-001',
    name: 'Caída de OSV nunca da un falso PASS',
    description: 'Ante 429, 500, 503, tiempo agotado o respuesta no JSON, el veredicto es INCOMPLETE (exit 3).',
    category: 'negative',
    severity: 'critical',
    recommendation: 'Revisar el manejo de SourceError en sources/osv.js y policy.js: "no comprobado" no es "sin vulnerabilidades".',
    async run() {
      const out = []
      for (const how of [429, 500, 503, 'timeout', 'garbage']) {
        const mock = fixtureMockFetch()
        mock.state.fail.batch = how
        const report = await scan(projectFiles('py-uv'), mockScanOptions(mock))
        check(report.verdict === 'INCOMPLETE' && report.exit_code === 3, `${how}: veredicto ${report.verdict}`)
        check(report.components.filter((c) => c.version).every((c) => c.status === 'error'), `${how}: componentes sin marcar como error`)
        out.push(`${how}: INCOMPLETE, exit 3`)
      }
      return out
    },
  },
  {
    id: 'NEG-002',
    name: 'Lockfile corrupto',
    description: 'Un package-lock.json con marcas de conflicto de merge da INCOMPLETE con un aviso parse_error.',
    category: 'negative',
    severity: 'critical',
    recommendation: 'Revisar el tratamiento de ParseError en engine.js.',
    async run() {
      const report = await fixtureScan('malformed')
      check(report.verdict === 'INCOMPLETE', `veredicto ${report.verdict}`)
      check(report.problems.some((p) => p.code === 'parse_error'), 'falta el aviso parse_error')
      return `INCOMPLETE (exit ${report.exit_code}) con parse_error`
    },
  },
  {
    id: 'NEG-003',
    name: 'Rutas con traversal',
    description: 'Rechaza rutas como ../etc/passwd e ignora directorios ocultos y node_modules.',
    category: 'negative',
    severity: 'high',
    recommendation: 'Revisar normalisePath y SKIP_DIRS en discovery.js.',
    run() {
      let threw = false
      try {
        discover([{ path: '../etc/passwd', content: '' }])
      } catch (e) {
        threw = e instanceof DiscoveryError
      }
      check(threw, 'se aceptó una ruta con ../')
      const { manifests } = discover([
        { path: 'node_modules/x/requirements.txt', content: 'a==1' },
        { path: '.git/requirements.txt', content: 'a==1' },
        { path: 'src/requirements.txt', content: 'a==1' },
      ])
      check(sameJson(manifests.map((m) => m.relPath), ['src/requirements.txt']), 'no se podaron node_modules/.git')
      return ['../etc/passwd rechazado', 'node_modules y .git ignorados']
    },
  },
  {
    id: 'NEG-004',
    name: 'Límites de tamaño y número de archivos',
    description: `Rechaza archivos de más de ${MAX_FILE_BYTES / 1024 / 1024} MB y más de ${MAX_FILES} archivos.`,
    category: 'negative',
    severity: 'medium',
    recommendation: 'Revisar MAX_FILE_BYTES, MAX_TOTAL_BYTES y MAX_FILES en discovery.js.',
    async run() {
      const big = await rejects(() => discover([{ path: 'requirements.txt', content: 'x'.repeat(MAX_FILE_BYTES + 1) }]), DiscoveryError, 'larger than')
      check(big, 'se aceptó un archivo demasiado grande')
      const many = Array.from({ length: MAX_FILES + 1 }, (_, i) => ({ path: `p${i}/requirements.txt`, content: 'a==1' }))
      check(await rejects(() => discover(many), DiscoveryError, 'too many files'), 'se aceptaron demasiados archivos')
      return [`archivo de ${MAX_FILE_BYTES + 1} bytes rechazado`, `${MAX_FILES + 1} archivos rechazados`]
    },
  },
  {
    id: 'NEG-005',
    name: 'Solo hosts permitidos y HTTPS',
    description: 'El cliente HTTP rechaza hosts no permitidos, http:// y javascript:, y permite el proxy KEV del mismo origen.',
    category: 'negative',
    severity: 'critical',
    recommendation: 'Revisar checkUrl y ALLOWED_HOSTS en sources/http.js.',
    async run() {
      let requests = 0
      const http = new HttpClient({
        fetchImpl: async () => (requests++, new Response('{}')),
        origin: 'https://demo.test',
        sleep: async () => {},
      })
      const refused = ['https://evil.example/x', 'http://api.osv.dev/v1/query', 'javascript:alert(1)']
      for (const url of refused) check(await rejects(http.getJson(url), SourceError), `no rechazada: ${url}`)
      check(requests === 0, `${requests} petición(es) salieron hacia URLs rechazadas`)
      check(sameJson(await http.getJson('/api/kev'), {}), 'el proxy /api/kev no responde')
      return [`${refused.length} URLs rechazadas sin realizar la petición`, `hosts permitidos: ${[...ALLOWED_HOSTS].join(', ')}`]
    },
  },
  {
    id: 'NEG-006',
    name: 'Respuesta demasiado grande',
    description: 'Una respuesta que supera el límite de tamaño se corta con un error controlado.',
    category: 'negative',
    severity: 'medium',
    recommendation: 'Revisar maxBytes en sources/http.js.',
    async run() {
      const http = new HttpClient({ fetchImpl: async () => new Response('x'.repeat(5000)), maxBytes: 1000, sleep: async () => {} })
      check(await rejects(http.getJson('https://api.osv.dev/v1/vulns/X'), SourceError, 'size limit'), 'no se aplicó el límite')
      return 'respuesta de 5000 bytes cortada con límite de 1000'
    },
  },
  {
    id: 'NEG-007',
    name: 'Archivo no soportado',
    description: 'Un archivo que no es un manifest es un error de la herramienta (exit 2), no un PASS vacío.',
    category: 'negative',
    severity: 'high',
    recommendation: 'Revisar discover() y la conversión a ToolError en engine.js.',
    async run() {
      const err = await rejects(scan([{ path: 'notes.md', content: 'hello' }], mockScanOptions(fixtureMockFetch())), ToolError)
      check(err, 'el archivo no soportado no produjo ToolError')
      return `ToolError: ${err.message}`
    },
  },
  {
    id: 'NEG-008',
    name: 'Claves __proto__ en un lockfile',
    description: 'Un lockfile con paquetes llamados __proto__ y constructor no contamina los prototipos de JavaScript.',
    category: 'negative',
    severity: 'high',
    recommendation: 'Usar Map u objetos sin prototipo (Object.create(null)) al indexar nombres de paquetes.',
    async run() {
      const lock = `{"name":"x","lockfileVersion":3,"packages":{
        "":{"name":"x","dependencies":{"__proto__":"1.0.0","constructor":"1.0.0","left-pad":"1.3.0"}},
        "node_modules/__proto__":{"version":"1.0.0","polluted":"yes"},
        "node_modules/constructor":{"version":"1.0.0"},
        "node_modules/left-pad":{"version":"1.3.0","dependencies":{"__proto__":"1.0.0"}}}}`
      const before = Object.getOwnPropertyNames(Object.prototype).join()
      let outcome
      try {
        const report = await scan([{ path: 'package-lock.json', content: lock }], mockScanOptions(fixtureMockFetch()))
        outcome = `escaneo completado: ${report.verdict}, ${report.summary.components} componentes`
      } catch (err) {
        check(err instanceof ToolError, `fallo no controlado: ${err?.name}: ${err?.message}`)
        outcome = `rechazado como error de la herramienta: ${err.message}`
      }
      check(Object.getOwnPropertyNames(Object.prototype).join() === before, 'Object.prototype fue modificado')
      check({}.polluted === undefined && {}.version === undefined, 'los objetos heredan propiedades del lockfile')
      return [outcome, 'Object.prototype intacto']
    },
  },
  {
    id: 'NEG-009',
    name: 'Fallo al obtener el detalle de un aviso',
    description: 'Si falla el detalle, el hallazgo se mantiene con severidad UNKNOWN y en producción no baja a P3.',
    category: 'negative',
    severity: 'high',
    recommendation: 'Revisar buildFindings en correlate.js y la regla de severidad desconocida en risk.js.',
    async run() {
      const mock = fixtureMockFetch()
      mock.state.fail.vuln = 503
      const report = await scan(projectFiles('py-uv'), mockScanOptions(mock))
      check(report.findings.length > 0, 'los hallazgos desaparecieron')
      check(report.findings.every((f) => f.severity === 'UNKNOWN'), 'severidad inventada sin datos')
      check(report.findings.filter((f) => f.package.scope === 'prod').every((f) => f.priority !== 'P3'), 'un hallazgo de producción bajó a P3')
      return `${report.findings.length} hallazgos conservados con severidad UNKNOWN`
    },
  },
]

const regression = [
  {
    id: 'REG-001',
    name: 'Tiempo agotado leyendo la respuesta',
    description: 'Un corte mientras se lee el cuerpo se reintenta en lugar de romper el escaneo.',
    category: 'regression',
    severity: 'high',
    recommendation: 'Mantener la lectura del cuerpo dentro del bloque de reintentos de sources/http.js.',
    async run() {
      let calls = 0
      const fetchImpl = async () => {
        calls++
        if (calls === 1) {
          const body = new ReadableStream({
            pull(controller) {
              controller.error(Object.assign(new Error('aborted'), { name: 'AbortError' }))
            },
          })
          return new Response(body, { status: 200 })
        }
        return new Response('{"ok": true}')
      }
      const http = new HttpClient({ fetchImpl, sleep: async () => {} })
      check(sameJson(await http.getJson('https://www.cisa.gov/feed.json'), { ok: true }), 'respuesta incorrecta tras reintento')
      check(calls === 2, `${calls} intentos`)
      return 'recuperado en el segundo intento'
    },
  },
  {
    id: 'REG-002',
    name: 'Reintento ante 429',
    description: 'Un 429 transitorio con Retry-After se reintenta y el escaneo termina con su veredicto real.',
    category: 'regression',
    severity: 'medium',
    recommendation: 'Revisar RETRY_STATUS y Retry-After en sources/http.js.',
    async run() {
      const mock = fixtureMockFetch()
      let first = true
      mock.state.fail.batch = () => {
        if (!first) return null
        first = false
        return new Response('{}', { status: 429, headers: { 'Retry-After': '1' } })
      }
      const report = await scan(projectFiles('py-uv'), mockScanOptions(mock))
      check(mock.state.calls.batch === 2, `${mock.state.calls.batch} llamadas a querybatch`)
      check(report.verdict === 'FAIL', `veredicto ${report.verdict}`)
      return '2 llamadas a querybatch, veredicto FAIL'
    },
  },
  {
    id: 'REG-003',
    name: 'Archivo .txt con otro nombre',
    description: 'Un único archivo .txt elegido explícitamente se analiza como requirements.',
    category: 'regression',
    severity: 'medium',
    recommendation: 'Revisar sniffAdapter en adapters/index.js.',
    async run() {
      const report = await scan([{ path: 'deps-prod.txt', content: 'acme-crypto==41.0.0\n' }], mockScanOptions(fixtureMockFetch()))
      check(report.manifests[0]?.adapter === 'pip-requirements', `adaptador ${report.manifests[0]?.adapter}`)
      check(report.summary.components === 1, `${report.summary.components} componentes`)
      return 'deps-prod.txt analizado como pip-requirements'
    },
  },
  {
    id: 'REG-004',
    name: 'La versión que corrige es posterior a la instalada',
    description: 'En todos los ecosistemas (npm, PyPI, Maven, Go) la versión recomendada es mayor que la actual.',
    category: 'regression',
    severity: 'high',
    recommendation: 'Revisar fixedVersions en correlate.js para el ecosistema afectado.',
    async run() {
      let checked = 0
      for (const project of ['npm-app', 'py-uv', 'py-poetry', 'sbom']) {
        const report = await fixtureScan(project)
        for (const f of report.findings) {
          for (const v of f.fixed_versions) {
            const cmp = compare(f.package.ecosystem, v, f.package.version)
            check(cmp === null || cmp > 0, `${f.package.name} ${f.package.version} -> ${v} (${f.package.ecosystem})`)
            checked++
          }
        }
      }
      check(checked > 0, 'no hubo versiones que comprobar')
      return `${checked} versiones de corrección comprobadas`
    },
  },
  {
    id: 'REG-005',
    name: 'Veredictos de las muestras de la demo',
    description: 'Cada ejemplo de la demo reproduce el veredicto y el número de hallazgos grabados en la instantánea.',
    category: 'regression',
    severity: 'high',
    recommendation: 'Si el cambio es intencionado, volver a grabar con npm run snapshot; si no, revisar el motor.',
    async run() {
      const snapshot = await loadSnapshot()
      const out = []
      for (const s of SAMPLES) {
        const expected = snapshot.verdicts[s.id]
        check(expected, `${s.id} no está en la instantánea`)
        const report = await snapshotScan(await loadSample(s.id), snapshot, async () => {
          throw new Error('network blocked')
        })
        check(report.verdict === expected.verdict, `${s.id}: ${report.verdict} en vez de ${expected.verdict}`)
        check(report.summary.findings === expected.findings, `${s.id}: ${report.summary.findings} hallazgos en vez de ${expected.findings}`)
        out.push(`${s.id}: ${report.verdict}, ${report.summary.findings} hallazgos`)
      }
      return out
    },
  },
  {
    id: 'REG-006',
    name: 'Configuración de despliegue coherente',
    description: 'netlify.toml declara exactamente las cabeceras probadas; la CSP no permite scripts en línea ni orígenes no usados.',
    category: 'regression',
    severity: 'high',
    recommendation: 'Sincronizar netlify.toml con security-headers.js y no relajar la CSP.',
    run() {
      const netlify = parseToml(PROJECT_FILES.netlifyToml)
      const served = netlify.headers.find((h) => h.for === '/*')?.values
      check(sameJson(served, SECURITY_HEADERS), 'netlify.toml y security-headers.js no coinciden')
      const csp = SECURITY_HEADERS['Content-Security-Policy']
      check(!/unsafe-(inline|eval)/.test(csp), 'la CSP permite unsafe-inline o unsafe-eval')
      const directive = (name) => csp.split(';').map((d) => d.trim()).find((d) => d.startsWith(`${name} `))
      check(directive('script-src') === "script-src 'self'", `script-src: ${directive('script-src')}`)
      const origins = directive('connect-src').split(' ').slice(2)
      check(origins.every((o) => ALLOWED_HOSTS.has(new URL(o).hostname)), `connect-src con origen no usado: ${origins.join(' ')}`)
      return [`${Object.keys(SECURITY_HEADERS).length} cabeceras idénticas`, "script-src 'self'", `connect-src: self ${origins.join(' ')}`]
    },
  },
]

const performance_ = [
  {
    id: 'PER-001',
    name: 'Escaneo de un proyecto real',
    description: `El ejemplo npm de la demo (lockfile real) se analiza en menos de ${PERF_BUDGET.sampleScanMs} ms (mediana de 3).`,
    category: 'performance',
    severity: 'medium',
    recommendation: 'Perfilar el adaptador npm y la correlación; evitar recorridos cuadráticos del grafo.',
    async run() {
      const snapshot = await loadSnapshot()
      const files = await loadSample('express-shop')
      const blocked = async () => {
        throw new Error('network blocked')
      }
      await snapshotScan(files, snapshot, blocked) // warm-up
      const times = []
      let components = 0
      for (let i = 0; i < 3; i++) {
        const t0 = performance.now()
        components = (await snapshotScan(files, snapshot, blocked)).summary.components
        times.push(performance.now() - t0)
      }
      const m = median(times)
      check(m < PERF_BUDGET.sampleScanMs, `mediana ${m.toFixed(0)} ms (presupuesto ${PERF_BUDGET.sampleScanMs} ms)`)
      return `${components} componentes, mediana ${m.toFixed(0)} ms (presupuesto ${PERF_BUDGET.sampleScanMs} ms)`
    },
  },
  {
    id: 'PER-002',
    name: 'Comparación de versiones a escala',
    description: `${PERF_BUDGET.versionCompares} comparaciones de versiones en menos de ${PERF_BUDGET.versionCompareMs} ms.`,
    category: 'performance',
    severity: 'low',
    recommendation: 'Revisar las expresiones regulares y la caché de claves en versions.js.',
    run() {
      const cases = readJson('golden/versions.json').cases
      const t0 = performance.now()
      for (let i = 0; i < PERF_BUDGET.versionCompares; i++) {
        const [eco, a, b] = cases[i % cases.length]
        compare(eco, a, b)
      }
      const ms = performance.now() - t0
      check(ms < PERF_BUDGET.versionCompareMs, `${ms.toFixed(0)} ms (presupuesto ${PERF_BUDGET.versionCompareMs} ms)`)
      return `${PERF_BUDGET.versionCompares} comparaciones en ${ms.toFixed(0)} ms`
    },
  },
  {
    id: 'PER-003',
    name: 'Descubrimiento con el máximo de archivos',
    description: `Clasificar ${MAX_FILES} archivos lleva menos de ${PERF_BUDGET.discoveryMs} ms.`,
    category: 'performance',
    severity: 'low',
    recommendation: 'Revisar walkOrder y la búsqueda de archivos hermanos en discovery.js.',
    run() {
      const names = ['requirements.txt', 'package.json', 'poetry.lock', 'notes.md', 'uv.lock']
      const files = Array.from({ length: MAX_FILES }, (_, i) => ({ path: `svc${i}/${names[i % names.length]}`, content: 'a==1' }))
      const t0 = performance.now()
      const { manifests } = discover(files)
      const ms = performance.now() - t0
      check(ms < PERF_BUDGET.discoveryMs, `${ms.toFixed(0)} ms (presupuesto ${PERF_BUDGET.discoveryMs} ms)`)
      return `${MAX_FILES} archivos, ${manifests.length} manifests en ${ms.toFixed(1)} ms`
    },
  },
]

const integrity = [
  {
    id: 'ITG-001',
    name: 'Informe determinista',
    description: 'Dos escaneos de la misma entrada producen informes con la misma huella SHA-256.',
    category: 'integrity',
    severity: 'high',
    recommendation: 'Eliminar fuentes de no determinismo (orden de mapas, fechas) del informe.',
    async run() {
      const a = await sha256Hex(canonicalJson(normalise(await fixtureScan('npm-app'))))
      const b = await sha256Hex(canonicalJson(normalise(await fixtureScan('npm-app'))))
      check(a === b, 'las huellas difieren')
      return `SHA-256 ${a.slice(0, 16)}… en ambas ejecuciones`
    },
  },
  {
    id: 'ITG-002',
    name: 'Caché grabada y reproducida',
    description: 'Lo grabado en caché y reproducido sin red da exactamente los mismos hallazgos que el escaneo en vivo.',
    category: 'integrity',
    severity: 'high',
    recommendation: 'Revisar dump/load de sources/cache.js y el modo offline.',
    async run() {
      const cache = new Cache()
      const live = await fixtureScan('py-uv', { cache })
      const replayCache = new Cache()
      replayCache.load(cache.dump())
      const mock = fixtureMockFetch()
      const replay = await scan(projectFiles('py-uv'), mockScanOptions(mock, { cache: replayCache, offline: true }))
      check(Object.values(mock.state.calls).every((n) => n === 0), 'la reproducción hizo peticiones')
      check(sameJson(replay.findings, live.findings), 'los hallazgos difieren')
      return `${live.findings.length} hallazgos idénticos, 0 peticiones en la reproducción`
    },
  },
  {
    id: 'ITG-003',
    name: 'Historial de calidad a prueba de manipulación',
    description: 'Un informe guardado se recupera intacto; uno modificado o un historial corrupto se rechaza.',
    category: 'integrity',
    severity: 'high',
    recommendation: 'Revisar verifyReport (report.js) y loadHistory (history.js).',
    async run() {
      const storage = memoryStorage()
      const sample = await buildReport({
        runId: 'self-test',
        startedAt: '2099-01-01T00:00:00.000Z',
        finishedAt: '2099-01-01T00:00:01.000Z',
        build: { fingerprint: 'f'.repeat(64) },
        environment: 'test',
        suiteSize: 1,
        results: [{ id: 'T-1', status: 'passed', severity: 'low', category: 'unit', duration_ms: 1, evidence: ['ok'] }],
      })
      check((await verifyReport(sample)).valid, 'un informe recién sellado no se verifica')
      await saveRun(sample, storage)
      const loaded = await loadHistory(storage)
      check(loaded.reports.length === 1 && sameJson(loaded.reports[0], sample), 'el informe no se recuperó intacto')
      const tampered = { ...sample, results: [{ ...sample.results[0], status: 'failed' }] }
      check(!(await verifyReport(tampered)).valid, 'se aceptó un informe modificado')
      const forged = { ...tampered, summary: { ...sample.summary } }
      storage.write('depguard.quality.history.v1', JSON.stringify([forged, sample]))
      const reloaded = await loadHistory(storage)
      check(reloaded.rejected === 1 && reloaded.reports.length === 1, 'el historial no descartó la entrada manipulada')
      storage.write('depguard.quality.history.v1', '{not json')
      check((await loadHistory(storage)).reports.length === 0, 'se aceptó un historial corrupto')
      return ['informe recuperado con huella válida', 'informe manipulado rechazado', 'historial corrupto descartado']
    },
  },
  {
    id: 'ITG-004',
    name: 'Huellas SARIF únicas',
    description: 'Cada resultado SARIF tiene una huella estable y única, y referencia una regla existente.',
    category: 'integrity',
    severity: 'medium',
    recommendation: 'Revisar partialFingerprints en reporters/sarif.js.',
    async run() {
      const run = (await toSarif(await fixtureScan('npm-app'))).runs[0]
      const rules = new Set(run.tool.driver.rules.map((r) => r.id))
      check(run.results.every((r) => rules.has(r.ruleId)), 'resultado con regla inexistente')
      const fps = run.results.map((r) => r.partialFingerprints['depguard/v1'])
      check(new Set(fps).size === fps.length, 'huellas duplicadas')
      return `${fps.length} resultados con huella única`
    },
  },
]

const dependencies = [
  {
    id: 'DEP-001',
    name: 'Procedencia del lockfile de la web',
    description: 'Cada paquete de web/package-lock.json procede del registro oficial de npm y tiene hash sha512.',
    category: 'dependencies',
    severity: 'high',
    recommendation: 'Regenerar el lockfile con npm contra el registro oficial; no aceptar paquetes sin integrity.',
    run() {
      const packages = Object.entries(JSON.parse(PROJECT_FILES.webLockfile).packages).filter(([path, p]) => path && !p.link)
      const bad = packages.filter(([, p]) => !p.resolved?.startsWith(NPM_REGISTRY) || !p.integrity?.startsWith('sha512-'))
      check(!bad.length, `${bad.length} paquete(s) sin procedencia verificable: ${bad.slice(0, 5).map(([path]) => path).join(', ')}`)
      return `${packages.length} paquetes con origen ${NPM_REGISTRY} e integridad sha512`
    },
  },
  {
    id: 'DEP-002',
    name: 'Scripts de instalación desactivados',
    description: 'Los paquetes con scripts de instalación no se ejecutan en la máquina de build (--ignore-scripts).',
    category: 'dependencies',
    severity: 'high',
    recommendation: 'Mantener NPM_FLAGS = "--ignore-scripts" en netlify.toml y npm ci --ignore-scripts en CI.',
    run() {
      const withScripts = Object.entries(JSON.parse(PROJECT_FILES.webLockfile).packages)
        .filter(([, p]) => p.hasInstallScript)
        .map(([path]) => path.replace(/^.*node_modules\//, ''))
      const flags = parseToml(PROJECT_FILES.netlifyToml).build?.environment?.NPM_FLAGS ?? ''
      check(flags.includes('--ignore-scripts'), 'netlify.toml no desactiva los scripts de instalación')
      return [`${withScripts.length} paquete(s) con scripts de instalación: ${withScripts.join(', ') || 'ninguno'}`, `NPM_FLAGS = ${flags}`]
    },
  },
  {
    id: 'DEP-003',
    name: 'Dependencias de ejecución mínimas',
    description: `La web solo depende en ejecución de ${APPROVED_RUNTIME_DEPS.join(', ')}.`,
    category: 'dependencies',
    severity: 'medium',
    recommendation: 'Justificar y revisar cualquier dependencia nueva de producción antes de añadirla a la lista aprobada.',
    run() {
      const deps = Object.keys(JSON.parse(PROJECT_FILES.webManifest).dependencies ?? {}).sort()
      const extra = deps.filter((d) => !APPROVED_RUNTIME_DEPS.includes(d))
      check(!extra.length, `dependencias no aprobadas: ${extra.join(', ')}`)
      const lock = JSON.parse(PROJECT_FILES.webLockfile).packages
      const missing = deps.filter((d) => !lock[`node_modules/${d}`] || lock[`node_modules/${d}`].dev)
      check(!missing.length, `no fijadas como producción en el lockfile: ${missing.join(', ')}`)
      return `${deps.length} dependencias de ejecución: ${deps.join(', ')}`
    },
  },
  {
    id: 'DEP-004',
    name: 'Vulnerabilidades conocidas en las dependencias de la web',
    description: 'DepGuard analiza su propio web/package-lock.json contra OSV.dev en vivo con la política por defecto.',
    category: 'dependencies',
    severity: 'critical',
    recommendation: 'Actualizar las dependencias señaladas (npm update / overrides) y volver a ejecutar las pruebas.',
    timeoutMs: 90_000,
    async run(ctx) {
      if (!ctx.network) skip('sin acceso a la red en este entorno: no se puede consultar OSV.dev')
      const report = await scan([{ path: 'package-lock.json', content: PROJECT_FILES.webLockfile }], {})
      if (report.sources.osv !== 'ok') skip(`OSV.dev no disponible (${report.sources.osv}): no hay evidencia`)
      const active = report.findings.filter((f) => f.status === 'active')
      check(
        report.verdict === 'PASS',
        `veredicto ${report.verdict}: ${active.slice(0, 5).map((f) => `${f.package.name}@${f.package.version} ${f.id} ${f.priority}`).join('; ')}`,
      )
      return [
        `veredicto PASS con ${report.summary.components} componentes`,
        `${active.length} hallazgo(s) por debajo del umbral de la política`,
        `fuentes: OSV ${report.sources.osv}, EPSS ${report.sources.epss}, KEV ${report.sources.kev}`,
      ]
    },
  },
]

export const SUITE = [...unit, ...integration, ...functional, ...negative, ...regression, ...performance_, ...integrity, ...dependencies]
