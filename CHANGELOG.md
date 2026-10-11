# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.0.0b2] - 2026-10-11

### Added
- Public web demo (`web/`): the engine ported to JavaScript, running in the
  browser (React + Vite + Tailwind, static hosting on Netlify), with live and
  recorded-snapshot modes, policy editor, simulated outage, and JSON / SARIF /
  CycloneDX downloads. Parity with the Python engine is enforced by the shared
  goldens.
- `scripts/check_text_safety.py`: CI fails on invisible/bidi characters.
- Security & quality center in the web demo: 46 real tests (unit, integration,
  functional, negative, regression, performance, integrity, dependencies) run
  in the browser or with `npm run quality`, sealed SHA-256 reports, verified
  local history, and a certificate of internal tests tied to the run and to a
  fingerprint of the evaluated code (docs/quality.md).

### Changed
- Liquid Metal Hero: procedural WebGL liquid-metal sphere (no 3D library),
  pointer-reactive aurora, halo, particles and light lines, staggered entrance,
  parallax layers, CSS fallback, reduced-motion still frame and adaptive
  resolution. Replaces the hero photo.
- Quality certificate: tests that cannot apply to the environment (served
  production headers on the dev server) are "No aplica" and no longer block
  the result, which made the certificate look stuck at "Evidencia insuficiente"
  in development. Reports move to depguard.quality/v2 (v1 still verifies).
- Web demo redesigned with far less text: a black hero with only the name and
  a one-line description next to a photo, and no Architecture or Demo vs CLI
  sections (those are covered in the docs).
- `web/package-lock.json` now resolves from registry.npmjs.org instead of a
  third-party mirror. All 276 integrity hashes were checked against the
  official registry and are unchanged. `web/.npmrc` pins the registry.

### Fixed
- Fixed-version selection for ecosystems without a dedicated comparator
  (Maven, Go, crates.io…, via SBOM): log4j-core 2.14.1 was advised to "upgrade"
  to the 2.12.2 backport. A conservative numeric comparator now picks 2.15.0;
  ambiguous qualifiers still yield "unknown order" instead of a guess.

## [1.0.0b1] - 2026-10-05

First beta of the rebuilt scanner. **Breaking changes in behaviour** compared
with 0.x, all of them fixes of incorrect results.

### Fixed
- Failed OSV lookups (network errors, timeouts, HTTP 429/5xx, invalid JSON)
  were reported as "SEGURO". They are now `error` components and make the
  scan `INCOMPLETE` (exit code 3).
- Version specifiers were scanned as if they were the installed version
  (`flask>=2.0` → 2.0, `urllib3!=1.25.0` → 1.25.0, `^4.18.2` → 4.18.2,
  `>=1.0.0 <2.0.0` → `1.0.02.0.0`). Only exact versions are queried now;
  everything else is reported as unresolved.
- Every finding was labelled "CRÍTICO"; severity now comes from CVSS or the
  advisory rating.
- The exit code was always 0; it now reflects the policy decision.
- Aliased advisories (GHSA/PYSEC/CVE for the same issue) were counted twice.
- The CI workflow lived in `github/` instead of `.github/` and never ran.

### Added
- Lockfiles with transitive dependencies and dependency paths:
  `package-lock.json`/`npm-shrinkwrap.json` (v2, v3), `poetry.lock`, `uv.lock`.
- CycloneDX JSON input (any purl ecosystem supported by OSV: Maven, Go,
  crates.io, NuGet, RubyGems, Packagist…).
- Directory scanning (`depguard scan .`) with safe discovery.
- OSV `querybatch`, advisory cache, retries with backoff, offline mode.
- CVSS v3.x scoring, FIRST EPSS and CISA KEV enrichment.
- Explainable P0–P3 prioritisation (docs/risk-model.md).
- `depguard.toml`: policies and ignores with mandatory reason and expiry.
- Outputs: JSON (`depguard.report/v1`), SARIF 2.1.0, CycloneDX 1.6 (with VEX
  analysis for ignored findings); `depguard sbom`.
- Exit codes 0/1/2/3; GitHub Action (`action.yml`).
- Installable package with the `depguard` command.

### Deprecated
- `dep_guard.parsers` (0.x API). Use `dep_guard.adapters` / `dep_guard.scan`.

### Removed
- `dep_guard.scanner` (replaced by `dep_guard.sources.osv`).
