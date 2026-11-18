# NIST SSDF (SP 800-218 v1.1) — evaluación de prácticas

Evaluación interna a 2026-11-18 de las prácticas del Secure Software
Development Framework aplicadas al desarrollo de DepGuard. Estados: **Cumple**
(comprobado internamente, con evidencia en el repositorio), **Parcial**,
**No cumple**, **Pendiente de verificación** (depende de configuración fuera
del repositorio que no se pudo inspeccionar).

## PO — Preparar la organización

| Práctica | Estado | Evidencia | Deficiencia / acción |
|---|---|---|---|
| PO.1 Definir requisitos de seguridad para el desarrollo | Cumple | `docs/security.md` (modelo de amenazas por componente), `SECURITY.md` (qué es una vulnerabilidad, plazos), matriz ASVS (`asvs-5.0.md`) | — |
| PO.2 Roles y responsabilidades | Parcial | Un mantenedor responsable (`pyproject.toml`, `SECURITY.md`); responsable por excepción en `security/excepciones.md` | Proyecto de una sola persona: sin separación de funciones ni revisión por pares |
| PO.3 Cadena de herramientas de soporte | Cumple | `ci.yml`, `security.yml`, `codeql.yml`, `scorecard.yml`, `release.yml`; herramientas con versión y SHA-256 fijados (`docs/devsecops.md`) | — |
| PO.4 Criterios para las comprobaciones de seguridad | Cumple | Política de fallo documentada (`docs/devsecops.md`), `depguard.toml` (P1/KEV/INCOMPLETE), umbral ZAP Medium, `npm audit --audit-level=high`, cobertura ≥ 85 % | — |
| PO.5 Entornos de desarrollo seguros | Parcial | Runners alojados por GitHub, permisos mínimos, `persist-credentials: false`, sin secretos en workflows, `npm ci --ignore-scripts` | Estaciones de desarrollo fuera del alcance del repositorio |

## PS — Proteger el software

| Práctica | Estado | Evidencia | Deficiencia / acción |
|---|---|---|---|
| PS.1 Proteger el código frente a accesos y manipulación | Pendiente de verificación | gitleaks sobre todo el historial (0 hallazgos), CODEOWNERS no existe, Scorecard informa | Verificar en GitHub: protección de `Principal`, revisiones obligatorias, 2FA, commits firmados |
| PS.2 Mecanismo para verificar la integridad de las releases | Cumple | `release.yml`: atestaciones de procedencia SLSA firmadas con Sigstore, `SHA256SUMS`, Trusted Publishing en PyPI; `gh attestation verify` documentado | Ninguna release se ha publicado aún con este flujo (acción del propietario: trusted publisher) |
| PS.3 Archivar y proteger cada release | Cumple | Artefactos, SBOM CycloneDX y SPDX adjuntos a la release de GitHub; etiquetas `vX.Y.Z` | — |

## PW — Producir software bien protegido

| Práctica | Estado | Evidencia | Deficiencia / acción |
|---|---|---|---|
| PW.1 Diseñar para cumplir requisitos y mitigar riesgos | Cumple | Diseño de fallo cerrado (`INCOMPLETE`), loopback + token + Host/Origin, raíces permitidas, parsers sin ejecución (`docs/security.md`) | — |
| PW.2 Revisar el diseño | Parcial | Auditoría interna (`audit/01-auditoria-inicial.md`), evaluación ASVS | Sin revisión de diseño independiente |
| PW.4 Reutilizar software bien protegido | Cumple | Parsers de la biblioteca estándar (`json`, `tomllib`, ElementTree), `packaging`, PyYAML `SafeLoader`, FastAPI/Starlette/uvicorn; decisión documentada de no añadir herramientas duplicadas | — |
| PW.5 Codificar con prácticas seguras | Cumple | ruff con reglas `S` (bandit), mypy `--strict`, `pydantic` estricto, sin primitivas de ejecución (test), saneado de texto externo | — |
| PW.6 Configurar la construcción para mejorar la seguridad | Cumple | Build reproducible (`SOURCE_DATE_EPOCH`), herramientas desde lock con hashes, `--no-isolation`, comprobación de contenido del wheel; Vite sin sourcemaps | — |
| PW.7 Revisar o analizar el código | Parcial | CodeQL `security-extended`, bandit, ruff `S`, eslint en cada push/PR | Sin revisión humana por pares (un solo mantenedor) |
| PW.8 Probar el ejecutable | Cumple | 316 tests pytest (cobertura 88 %), 139 vitest, e2e Playwright (demo y app local), DAST ZAP autenticado, validación SBOM contra esquemas oficiales, comparación con OSV-Scanner (`audit/03-informe-pruebas.md`) | Ejecuciones en GitHub Actions pendientes del primer push |
| PW.9 Configuración segura por defecto | Cumple | Bind a 127.0.0.1 sin opción, raíz = carpeta personal, `fail_on_incomplete=true`, `fail_on_kev=true`, sin redirecciones, `--latest`/`--nvd` opcionales en CLI | — |

## RV — Responder a vulnerabilidades

| Práctica | Estado | Evidencia | Deficiencia / acción |
|---|---|---|---|
| RV.1 Identificar y confirmar vulnerabilidades de forma continua | Cumple | `security.yml` diario, Dependabot semanal, autoescaneo con DepGuard, informe privado de vulnerabilidades (`SECURITY.md`) | Activar «private vulnerability reporting» en GitHub (acción del propietario) |
| RV.2 Evaluar, priorizar y corregir | Cumple | Plazos por severidad (`SECURITY.md`), registro de excepciones con caducidad, priorización P0–P3 propia | — |
| RV.3 Analizar las causas raíz | Cumple | `audit/02-registro-vulnerabilidades.md` incluye causa y prueba de regresión para cada defecto | — |

## Resumen

| Grupo | Cumple | Parcial | Pendiente de verificación |
|---|---|---|---|
| PO (5) | 3 | 2 | 0 |
| PS (3) | 2 | 0 | 1 |
| PW (8) | 6 | 2 | 0 |
| RV (3) | 3 | 0 | 0 |
| **Total (19)** | **14** | **4** | **1** |

Las prácticas parciales se deben a que el proyecto tiene un único mantenedor
(sin separación de funciones ni revisión por pares). PS.1 depende de la
configuración de la organización en GitHub, que no se puede comprobar desde
el repositorio.
