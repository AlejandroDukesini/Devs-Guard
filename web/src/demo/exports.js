// Report downloads, generated locally (nothing is uploaded anywhere).

import { toSarif } from '../core/reporters/sarif.js'
import { toCycloneDx } from '../core/reporters/cyclonedx.js'

function download(filename, data, type) {
  const blob = new Blob([JSON.stringify(data, null, 2) + '\n'], { type })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.rel = 'noopener'
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export const EXPORTS = [
  { id: 'json', label: 'JSON', hint: 'depguard.report/v1, igual que la CLI' },
  { id: 'sarif', label: 'SARIF', hint: 'Para GitHub code scanning' },
  { id: 'cyclonedx', label: 'CycloneDX', hint: 'SBOM + vulnerabilidades (VEX)' },
]

export async function exportReport(kind, report, projectName = 'project') {
  if (kind === 'json') return download('depguard-report.json', report, 'application/json')
  if (kind === 'sarif') return download('depguard.sarif', await toSarif(report), 'application/sarif+json')
  if (kind === 'cyclonedx')
    return download('bom.cdx.json', toCycloneDx(report, projectName), 'application/vnd.cyclonedx+json')
  throw new Error(`unknown export ${kind}`)
}
