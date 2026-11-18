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
- In the local web app (`depguard serve`): any way for another web page, a
  DNS-rebinding host or another origin to use the API; reading or listing
  files outside the allowed folders (`--root`); using a session token after
  it expired or was ended; exposing the token in logs or responses.

## What is *not* a vulnerability in DepGuard

- A missing or wrong advisory in OSV.dev, EPSS or CISA KEV: report it upstream
  (<https://github.com/google/osv.dev>, the original advisory database).
- False positives/negatives caused by documented limitations
  (see [docs/limitations.md](docs/limitations.md)); please open a regular issue.

## Remediation time frames

For vulnerabilities in DepGuard itself and in the components it ships
(counted from confirmation; tracked in a private GitHub security advisory):

| Severity (CVSS) | Fix released within |
|---|---|
| Critical (9.0–10) | 7 days |
| High (7.0–8.9) | 30 days |
| Medium (4.0–6.9) | 90 days |
| Low (< 4.0) | next regular release |

The same time frames apply to third-party components: CI fails on any known
vulnerability in DepGuard's own lockfiles (docs/devsecops.md), and Dependabot
proposes updates weekly. An exception requires an entry in
[docs/security/excepciones.md](docs/security/excepciones.md) with an expiry.

## Status of security validation

DepGuard has been evaluated internally against OWASP ASVS 5.0, NIST SSDF
(SP 800-218) and OWASP SAMM; see [docs/compliance/](docs/compliance/). This is
a self-assessment, **not a certification**: no independent penetration test
or third-party audit has been performed yet.

## Threat model and hardening

See [docs/security.md](docs/security.md).
