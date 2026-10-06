# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 1.x     | ✅        |
| 0.x     | ❌ (known to report failed lookups as "safe"; upgrade) |

## Reporting a vulnerability

Please **do not open a public issue** for security problems in DepGuard itself.

Use GitHub's private reporting: **Security → Report a vulnerability** on
<https://github.com/AlejandroDukesini/Devs-Guard/security/advisories/new>.

Include the DepGuard version (`depguard --version`), the command you ran and,
if possible, a minimal manifest that reproduces the issue. You will get an
acknowledgement within 7 days. Fixes are released as patch versions and
credited in the advisory unless you prefer otherwise.

## What counts as a vulnerability in DepGuard

- A crafted manifest, lockfile, SBOM or advisory that makes DepGuard execute
  code, read files outside the scan root, contact hosts other than the
  documented sources, or corrupt/hide terminal, SARIF or JSON output.
- A failure mode where DepGuard reports **PASS** although it could not check a
  dependency (this is a security bug, not a usability bug).
- Leaking credentials found in manifests (e.g. index URLs) into output or logs.

## What is *not* a vulnerability in DepGuard

- A missing or wrong advisory in OSV.dev, EPSS or CISA KEV: report it upstream
  (<https://github.com/google/osv.dev>, the original advisory database).
- False positives/negatives caused by documented limitations
  (see [docs/limitations.md](docs/limitations.md)); please open a regular issue.

## Threat model and hardening

See [docs/security.md](docs/security.md).
