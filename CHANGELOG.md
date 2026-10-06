# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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
