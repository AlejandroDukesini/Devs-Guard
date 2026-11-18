# Formatos de salida

| Formato | Para qué | Opción |
|---|---|---|
| Tabla | Personas en una terminal | por defecto |
| JSON | Automatización, integraciones, la demo web | `-f json` |
| SARIF 2.1.0 | GitHub code scanning y paneles de seguridad | `-f sarif` |
| CycloneDX 1.6 | Intercambio SBOM + VEX con otras herramientas | `-f cyclonedx` o `depguard sbom` |
| SPDX 2.3 | SBOM para procesos y herramientas que exigen SPDX | `-f spdx` o `depguard sbom -f spdx` |

Los SBOM CycloneDX y SPDX se validan en CI contra los esquemas oficiales
(`scripts/validate_sbom.py`).

Con `-o archivo` el informe se escribe en disco; los mensajes de progreso y
el veredicto van siempre a *stderr*, así que *stdout* es parseable.

## JSON (`depguard.report/v1`)

Esquema estable (cambios incompatibles = nueva versión de esquema):

```jsonc
{
  "schema": "depguard.report/v1",
  "tool": {"name": "depguard", "version": "1.0.0b2"},
  "generated_at": "2026-10-05T12:00:00+00:00",
  "verdict": "FAIL",              // PASS | FAIL | INCOMPLETE
  "exit_code": 1,
  "summary": {"components": 8, "findings": 5, "by_priority": {"P0": 1, "P1": 2, "P2": 1, "P3": 1}, "...": "..."},
  "policy": {"violations": [], "incomplete_reasons": [], "expired_ignores": [], "unused_ignores": []},
  "sources": {"osv": "ok", "nvd": "disabled", "epss": "ok", "kev": "ok", "registries": "ok"},
  "manifests": [{"path": "package-lock.json", "adapter": "npm-package-lock", "components": 8, "error": null}],
  "findings": [{
    "id": "CVE-2099-1001", "aliases": ["CVE-2099-1001", "GHSA-…"],
    "summary": "…", "severity": "HIGH", "cvss": {"score": 7.5, "vector": "CVSS:3.1/…"},
    "package": {"name": "acme-qs", "version": "6.2.0", "purl": "pkg:npm/acme-qs@6.2.0",
                "direct": false, "scope": "prod", "paths": [["acme-router", "acme-qs"]],
                "locations": [{"file": "package-lock.json", "line": 31}]},
    "fixed_versions": ["6.2.4"], "published": "…", "modified": "…",
    "severity_source": "cvss_v3",  // cvss_v3 | advisory_label | nvd_cvss_v3 | nvd_cvss_v4 | none
    "epss": {"score": 0.62, "percentile": 0.99}, "kev": true,
    "priority": "P0", "reasons": [{"code": "kev", "text": "…"}],
    "status": "active", "ignore": null
  }],
  "remediation": [{"package": "acme-qs", "current": "6.2.0", "upgrade_to": "6.2.4",
                   "breaking": false, "fixes": 1, "of": 1}],
  "components": [{
    /* todos, con status clean|vulnerable|unresolved|private|error */
    "latest": "6.9.0", "latest_vulnerable": true,
    "patch_status": "vulnerable_fix_available",
    "patch_note": "actualizar a 6.2.4 (corrige 1 de 1); la última versión 6.9.0 también está afectada"
  }],
  "problems": [{"code": "no_lockfile", "message": "…", "file": "package.json"}],
  "stats": {"total_ms": 812.4, "http_requests": 7, "cache_hits": 3}
}
```

`kev`, `epss`, `latest` y `latest_vulnerable` valen `null` cuando no se
consultaron o no estaban disponibles: **null significa "desconocido", no "no"**.

### Estado de parche (`patch_status`)

| Valor | Significado |
|---|---|
| `up_to_date` | Sin avisos conocidos y en la última versión estable |
| `outdated` | Sin avisos conocidos; hay una versión estable más nueva |
| `vulnerable_fix_available` | Con avisos, y todos tienen versión corregida |
| `vulnerable_no_fix` | Con avisos, y al menos uno sin versión corregida |
| `no_known_vulnerabilities` | Sin avisos; última versión no consultada o no comparable |
| `insufficient_data` | La consulta falló o el paquete es privado |
| `unidentifiable_version` | Sin versión exacta (rango, git, ruta local…) |

`breaking: true` en la remediación indica un salto de versión mayor (o de
versión menor en `0.x`): puede romper la compatibilidad.

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
