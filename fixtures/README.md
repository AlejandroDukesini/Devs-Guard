# Shared test fixtures

These files are the **parity contract** between the Python engine (`dep_guard/`)
and the JavaScript engine of the web demo (`web/src/core/`). Both test suites
load the same inputs and must produce the same outputs.

- `projects/` — manifests and lockfiles. All package names (`acme-*`,
  `left-pad-plus`, `@acme/*`) are fictional.
- `osv-mock/` — a fake OSV/EPSS/KEV universe. Every advisory id and CVE
  (`CVE-2099-*`) is synthetic: no real vulnerability data is used in tests.
- `golden/` — expected results:
  - `versions.json`, `cvss.json`: algorithm tables;
  - `parsers.json`: components each adapter must extract;
  - `risk.json`: priority decisions;
  - `report-*.json`: full normalised `depguard.report/v1` for end-to-end scans
    against `osv-mock` (volatile fields `generated_at`, `stats`, `tool` removed).

Regenerate report goldens only after reviewing the diff:
`python -m tests.regen_golden` (Python is the reference implementation).
