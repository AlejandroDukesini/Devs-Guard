import { Priority } from './FindingRow.jsx'
import { REPO_URL } from '../links.js'

const PIPELINE = ['Descubrir', 'Parsear', 'Consultar', 'Correlacionar', 'Priorizar', 'Decidir']

const RULES = [
  ['P0', 'Producción y explotación activa (KEV o EPSS alto con severidad alta)'],
  ['P1', 'Severidad alta en producción, EPSS alto o KEV'],
  ['P2', 'Severidad media o desconocida en producción; alta solo en desarrollo'],
  ['P3', 'El resto'],
]

const EXIT_CODES = [
  ['0', 'PASS'],
  ['1', 'FAIL'],
  ['2', 'ERROR'],
  ['3', 'INCOMPLETE'],
]

export function HowItWorks() {
  return (
    <section id="como-funciona" className="scroll-mt-16 border-t border-slate-200 py-16 dark:border-slate-800">
      <div className="mx-auto max-w-6xl px-4 sm:px-6">
        <h2 className="section-title">Cómo funciona</h2>
        <ol className="mt-8 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
          {PIPELINE.map((step, i) => (
            <li key={step} className="card p-4">
              <p className="font-mono text-xs text-accent-700 dark:text-accent-500">0{i + 1}</p>
              <p className="mt-1 font-medium text-slate-900 dark:text-white">{step}</p>
            </li>
          ))}
        </ol>

        <div className="mt-10 grid gap-6 lg:grid-cols-[3fr_2fr]">
          <table className="card w-full min-w-0 overflow-hidden text-sm">
            <caption className="sr-only">Prioridades</caption>
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
          <div className="flex min-w-0 flex-col gap-3">
            <ul className="grid grid-cols-2 gap-2">
              {EXIT_CODES.map(([code, verdict]) => (
                <li key={code} className="card p-3 font-mono text-sm">
                  exit <strong>{code}</strong> · {verdict}
                </li>
              ))}
            </ul>
            <pre className="overflow-x-auto rounded-lg bg-slate-950 p-4 font-mono text-sm text-slate-100">
              <code>{`pip install "git+${REPO_URL}@Beta"
depguard scan .`}</code>
            </pre>
          </div>
        </div>
      </div>
    </section>
  )
}

export function Footer() {
  return (
    <footer className="border-t border-slate-200 py-8 text-sm text-slate-500 dark:border-slate-800">
      <div className="mx-auto flex max-w-6xl flex-wrap justify-between gap-4 px-4 sm:px-6">
        <p>DepGuard · MIT</p>
        <p className="flex gap-4">
          <a className="hover:underline" href={REPO_URL} target="_blank" rel="noopener noreferrer">GitHub</a>
          <a className="hover:underline" href="https://osv.dev" target="_blank" rel="noopener noreferrer">OSV.dev</a>
          <a className="hover:underline" href="https://www.first.org/epss/" target="_blank" rel="noopener noreferrer">EPSS</a>
          <a className="hover:underline" href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener noreferrer">CISA KEV</a>
        </p>
      </div>
    </footer>
  )
}
