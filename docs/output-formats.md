# Formatos de salida

| Formato | Para qué | Opción |
|---|---|---|
| Tabla | Personas en una terminal | por defecto |
| JSON | Automatización, integraciones, la demo web | `-f json` |
| SARIF 2.1.0 | GitHub code scanning y paneles de seguridad | `-f sarif` |
| CycloneDX 1.6 | Intercambio SBOM + VEX con otras herramientas | `-f cyclonedx` o `depguard sbom` |

Con `-o archivo` el informe se escribe en disco; los mensajes de progreso y
el veredicto van siempre a *stderr*, así que *stdout* es parseable.

## JSON (`depguard.report/v1`)

Esquema estable (cambios incompatibles = nueva versión de esquema):

```jsonc
{
  "schema": "depguard.report/v1",
  "tool": {"name": "depguard", "version": "1.0.0b1"},
  "generated_at": "2026-10-05T12:00:00+00:00",
  "verdict": "FAIL",              // PASS | FAIL | INCOMPLETE
  "exit_code": 1,
  "summary": {"components": 8, "findings": 5, "by_priority": {"P0": 1, "P1": 2, "P2": 1, "P3": 1}, "...": "..."},
  "policy": {"violations": [], "incomplete_reasons": [], "expired_ignores": [], "unused_ignores": []},
  "sources": {"osv": "ok", "epss": "ok", "kev": "ok"},
  "manifests": [{"path": "package-lock.json", "adapter": "npm-package-lock", "components": 8, "error": null}],
  "findings": [{
    "id": "CVE-2099-1001", "aliases": ["CVE-2099-1001", "GHSA-…"],
    "summary": "…", "severity": "HIGH", "cvss": {"score": 7.5, "vector": "CVSS:3.1/…"},
    "package": {"name": "acme-qs", "version": "6.2.0", "purl": "pkg:npm/acme-qs@6.2.0",
                "direct": false, "scope": "prod", "paths": [["acme-router", "acme-qs"]],
                "locations": [{"file": "package-lock.json", "line": 31}]},
    "fixed_versions": ["6.2.4"], "epss": {"score": 0.62, "percentile": 0.99}, "kev": true,
    "priority": "P0", "reasons": [{"code": "kev", "text": "…"}],
    "status": "active", "ignore": null
  }],
  "remediation": [{"package": "acme-qs", "current": "6.2.0", "upgrade_to": "6.2.4", "fixes": 1, "of": 1}],
  "components": [ /* todos, con status clean|vulnerable|unresolved|private|error */ ],
  "problems": [{"code": "no_lockfile", "message": "…", "file": "package.json"}],
  "stats": {"total_ms": 812.4, "http_requests": 7, "cache_hits": 3}
}
```

`kev` y `epss` valen `null` cuando no se consultaron o no estaban
disponibles: **null significa "desconocido", no "no"**.

## SARIF

- Una regla por vulnerabilidad, con `security-severity` (CVSS o equivalente).
- Un resultado por paquete@versión afectado, ubicado en la línea del lockfile.
- Nivel: P0/P1 → `error`, P2 → `warning`, P3 → `note`.
- Los ignorados llevan `suppressions` con la justificación y la caducidad.
- `partialFingerprints` estables para que GitHub no duplique alertas.

## CycloneDX

- `components` con purl, `scope` (`required` / `excluded` para dev) y el grafo `dependencies`.
- `vulnerabilities` con `ratings`, `cwes`, `affects`, recomendación y
  propiedades `depguard:priority` y `depguard:reasons`.
- Las excepciones se exportan como `analysis` (VEX) con estado `in_triage` y el motivo.
- El SBOM generado se puede volver a escanear: `depguard scan bom.cdx.json`.
