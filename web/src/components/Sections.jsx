import { Priority } from './FindingRow.jsx'
import { REPO_URL, doc } from '../links.js'

const PIPELINE = [
  ['Descubrir', 'Encuentra lockfiles, manifests y SBOM. Un lockfile sustituye al package.json de su carpeta.'],
  ['Parsear', 'Extrae paquete, versión exacta, ámbito prod/dev y la ruta desde la dependencia directa.'],
  ['Consultar', 'OSV.dev en lote (querybatch) por versión exacta; detalles cacheados por id@modified.'],
  ['Correlacionar', 'Agrupa alias (CVE/GHSA/PYSEC), calcula CVSS v3 y la versión que corrige.'],
  ['Priorizar', 'Tabla de decisión con KEV, EPSS, severidad y ámbito: P0–P3 con motivos.'],
  ['Decidir', 'Aplica la política y las excepciones con caducidad: PASS, FAIL o INCOMPLETE.'],
]

const RULES = [
  ['P0', 'En producción y (en CISA KEV o EPSS ≥ 0,10 con severidad ≥ HIGH)'],
  ['P1', 'Severidad ≥ HIGH en producción, o EPSS ≥ 0,10, o en KEV'],
  ['P2', 'MEDIUM o severidad desconocida en producción; HIGH+ solo en desarrollo'],
  ['P3', 'El resto'],
]

export function HowItWorks() {
  return (
    <section id="como-funciona" className="border-t border-slate-200 py-16 dark:border-slate-800">
      <div className="mx-auto max-w-6xl px-4 sm:px-6">
        <h2 className="section-title">Cómo funciona</h2>
        <ol className="mt-8 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {PIPELINE.map(([title, text], i) => (
            <li key={title} className="card p-4">
              <p className="font-mono text-xs text-accent-700 dark:text-accent-500">0{i + 1}</p>
              <p className="mt-1 font-medium text-slate-900 dark:text-white">{title}</p>
              <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">{text}</p>
            </li>
          ))}
        </ol>

        <div className="mt-12 grid gap-8 lg:grid-cols-[1fr_1fr]">
          <div>
            <h3 className="text-lg font-semibold text-slate-900 dark:text-white">Prioridad explicable, no una puntuación opaca</h3>
            <p className="mt-2 text-sm text-slate-600 dark:text-slate-400">
              Las reglas se evalúan de arriba abajo. Lo desconocido nunca tranquiliza: un ámbito desconocido cuenta como
              producción y una severidad desconocida es como mínimo P2. Cada hallazgo muestra los motivos de su prioridad.
            </p>
            <a href={doc('docs/risk-model.md')} target="_blank" rel="noopener noreferrer" className="mt-3 inline-block text-sm text-accent-700 hover:underline dark:text-accent-500">
              Modelo de riesgo completo →
            </a>
          </div>
          <table className="card w-full overflow-hidden text-sm">
            <caption className="sr-only">Tabla de decisión de prioridades</caption>
            <tbody>
              {RULES.map(([p, rule]) => (
                <tr key={p} className="border-b border-slate-200 last:border-0 dark:border-slate-800">
                  <th scope="row" className="w-14 p-3 text-left align-top">
                    <Priority value={p} />
                  </th>
                  <td className="p-3 text-slate-700 dark:text-slate-300">{rule}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="mt-12 grid gap-4 sm:grid-cols-3">
          {[
            ['0', 'PASS', 'Política cumplida y todo comprobado'],
            ['1', 'FAIL', 'Política incumplida'],
            ['3', 'INCOMPLETE', 'Algo no se pudo comprobar (red, OSV, archivo corrupto)'],
          ].map(([code, v, text]) => (
            <div key={code} className="card p-4">
              <p className="font-mono text-sm">
                exit <strong>{code}</strong> · {v}
              </p>
              <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">{text}</p>
            </div>
          ))}
        </div>
        <p className="mt-3 text-sm text-slate-500">
          exit 2 = error de la herramienta (argumentos, configuración inválida, archivo no soportado).
        </p>
      </div>
    </section>
  )
}

function Box({ title, children, accent = false }) {
  return (
    <div className={`card p-4 ${accent ? 'border-accent-600 dark:border-accent-500' : ''}`}>
      <p className="font-medium text-slate-900 dark:text-white">{title}</p>
      <div className="mt-1 text-sm text-slate-600 dark:text-slate-400">{children}</div>
    </div>
  )
}

const Arrow = () => (
  <div className="flex justify-center py-2 text-slate-400" aria-hidden="true">
    ↓
  </div>
)

export function Architecture() {
  return (
    <section id="arquitectura" className="border-t border-slate-200 py-16 dark:border-slate-800">
      <div className="mx-auto max-w-6xl px-4 sm:px-6">
        <h2 className="section-title">Arquitectura real</h2>
        <p className="mt-2 max-w-3xl text-slate-600 dark:text-slate-400">
          No hay servidor propio. La demo es un sitio estático; el escaneo ocurre en tu navegador con un port en
          JavaScript del motor de Python, y ambos se verifican contra los mismos casos de prueba.
        </p>
        <div className="mt-8 grid gap-6 lg:grid-cols-2">
          <div>
            <p className="label mb-2">Demo web (esta página)</p>
            <Box title="Navegador">React + Vite. Tus archivos se leen localmente con la File API.</Box>
            <Arrow />
            <Box title="Motor JS (web/src/core)" accent>
              Adaptadores, correlación, riesgo, política y exportación SARIF/CycloneDX.
            </Box>
            <Arrow />
            <div className="grid grid-cols-3 gap-2 text-center text-xs">
              <Box title="OSV.dev">CORS directo</Box>
              <Box title="FIRST EPSS">CORS directo</Box>
              <Box title="CISA KEV">vía rewrite de Netlify (/api/kev)</Box>
            </div>
          </div>
          <div>
            <p className="label mb-2">CLI (instalación local / CI)</p>
            <Box title="Terminal o pipeline">depguard scan . · GitHub Action · GitLab · Jenkins</Box>
            <Arrow />
            <Box title="Motor Python (dep_guard/)" accent>
              El original: misma lógica, más ecosistemas en disco, caché persistente, modo offline.
            </Box>
            <Arrow />
            <Box title="Paridad verificada">
              <code className="font-mono">fixtures/golden/*.json</code> se ejecutan en pytest y en vitest. Si los motores
              divergen, falla el CI.
            </Box>
          </div>
        </div>
      </div>
    </section>
  )
}

const DIFFS = [
  ['Entrada', 'Archivos que eliges o pegas (máx. 2 MB c/u, 200 archivos)', 'Directorios completos, sin límites prácticos'],
  ['Datos', 'En vivo o instantánea grabada de los ejemplos', 'En vivo, caché en disco y modo --offline'],
  ['KEV', 'Vía rewrite de Netlify (CISA no permite CORS)', 'Directo a cisa.gov'],
  ['Integración', 'Descarga de JSON, SARIF y CycloneDX', 'Exit codes para CI, GitHub Action, SARIF a code scanning'],
  ['Privacidad', 'Archivos en tu navegador; nombre+versión a OSV', 'Igual, más private_packages en depguard.toml'],
  ['Configuración', 'depguard.toml editable en la página', 'depguard.toml en el repositorio'],
]

export function DemoVsLocal() {
  return (
    <section id="demo-vs-local" className="border-t border-slate-200 py-16 dark:border-slate-800">
      <div className="mx-auto max-w-6xl px-4 sm:px-6">
        <h2 className="section-title">Demo frente a CLI</h2>
        <div className="mt-6 overflow-x-auto">
          <table className="card w-full min-w-[36rem] text-sm">
            <thead>
              <tr className="border-b border-slate-200 text-left dark:border-slate-800">
                <th scope="col" className="p-3 label">Aspecto</th>
                <th scope="col" className="p-3 label">Demo web</th>
                <th scope="col" className="p-3 label">CLI</th>
              </tr>
            </thead>
            <tbody>
              {DIFFS.map(([k, a, b]) => (
                <tr key={k} className="border-b border-slate-200 last:border-0 dark:border-slate-800">
                  <th scope="row" className="p-3 text-left font-medium text-slate-900 dark:text-white">{k}</th>
                  <td className="p-3 text-slate-600 dark:text-slate-400">{a}</td>
                  <td className="p-3 text-slate-600 dark:text-slate-400">{b}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="mt-8 card p-5">
          <p className="font-medium text-slate-900 dark:text-white">Instalar la CLI</p>
          <pre className="mt-3 overflow-x-auto rounded-lg bg-slate-950 p-4 font-mono text-sm text-slate-100">
            <code>{`pip install "git+${REPO_URL}@Beta"
depguard scan .
depguard scan . -f sarif -o depguard.sarif`}</code>
          </pre>
        </div>
      </div>
    </section>
  )
}

export function Footer() {
  return (
    <footer className="border-t border-slate-200 py-10 text-sm text-slate-500 dark:border-slate-800">
      <div className="mx-auto flex max-w-6xl flex-col gap-4 px-4 sm:flex-row sm:justify-between sm:px-6">
        <p>
          DepGuard · licencia MIT ·{' '}
          <a className="hover:underline" href={REPO_URL} target="_blank" rel="noopener noreferrer">
            código en GitHub
          </a>{' '}
          ·{' '}
          <a className="hover:underline" href={doc('docs/limitations.md')} target="_blank" rel="noopener noreferrer">
            limitaciones
          </a>
        </p>
        <p>
          Datos:{' '}
          <a className="hover:underline" href="https://osv.dev" target="_blank" rel="noopener noreferrer">OSV.dev</a>,{' '}
          <a className="hover:underline" href="https://www.first.org/epss/" target="_blank" rel="noopener noreferrer">FIRST EPSS</a>,{' '}
          <a className="hover:underline" href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener noreferrer">CISA KEV</a>
        </p>
      </div>
    </footer>
  )
}
