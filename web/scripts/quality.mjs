// `npm run quality`: runs the quality suite (the same one the web runs) under
// vitest and writes the sealed report to reports/quality-report.json.
// Exit code is vitest's: non-zero if any test failed or errored.

import { spawnSync } from 'node:child_process'

const out = 'reports/quality-report.json'
const { status } = spawnSync('npx', ['vitest', 'run', 'tests/quality.test.jsx'], {
  stdio: 'inherit',
  shell: process.platform === 'win32',
  env: { ...process.env, QUALITY_REPORT: out },
})
if (status === 0) console.log(`quality report: ${out}`)
process.exit(status ?? 1)
