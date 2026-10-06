import { GitHubIcon } from './Icons.jsx'
import { REPO_URL, doc } from '../links.js'

const POINTS = [
  ['Lockfiles y SBOM', 'npm, Poetry, uv, pip y CycloneDX, con dependencias transitivas.'],
  ['Prioridad explicable', 'CVSS + EPSS + CISA KEV + contexto: P0–P3 y el porqué.'],
  ['Resultado honesto', '"No se pudo comprobar" nunca se convierte en "sin vulnerabilidades".'],
]

export default function Hero() {
  return (
    <section id="top" className="border-b border-slate-200 dark:border-slate-800">
      <div className="mx-auto max-w-6xl px-4 py-14 sm:px-6 sm:py-20">
        <p className="label text-accent-700 dark:text-accent-500">Escáner de dependencias · DevSecOps</p>
        <h1 className="mt-3 max-w-3xl text-3xl font-semibold tracking-tight text-balance text-slate-900 sm:text-5xl dark:text-white">
          Qué vulnerabilidades corregir primero, y por qué.
        </h1>
        <p className="mt-5 max-w-2xl text-lg text-pretty text-slate-600 dark:text-slate-400">
          DepGuard lee tus lockfiles, consulta OSV.dev y prioriza cada vulnerabilidad con datos de explotación real. Esta
          demo ejecuta el mismo motor en tu navegador: los archivos no salen de tu equipo.
        </p>
        <div className="mt-8 flex flex-wrap gap-3">
          <a href="#demo" className="btn-primary px-5 py-2.5">
            Probar la demo
          </a>
          <a href={REPO_URL} className="btn-secondary px-5 py-2.5" target="_blank" rel="noopener noreferrer">
            <GitHubIcon /> Ver código
          </a>
          <a href={doc('README.md')} className="btn-ghost px-3 py-2.5" target="_blank" rel="noopener noreferrer">
            Documentación →
          </a>
        </div>
        <dl className="mt-12 grid gap-6 sm:grid-cols-3">
          {POINTS.map(([title, text]) => (
            <div key={title} className="border-l-2 border-accent-600 pl-4">
              <dt className="font-medium text-slate-900 dark:text-white">{title}</dt>
              <dd className="mt-1 text-sm text-slate-600 dark:text-slate-400">{text}</dd>
            </div>
          ))}
        </dl>
      </div>
    </section>
  )
}
