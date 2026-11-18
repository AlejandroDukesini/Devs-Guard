# Informe técnico final — DEPS-GUARD

- Fecha: 2026-11-18. Rama `Beta`, commits `428c00a` … (ver `git log`).
- Punto de partida: `9cb8b56` (release 1.0.0b2).
- Este informe permite comprobar qué se hizo: cada afirmación remite a un
  archivo, un test o una ejecución reproducible.

## A. Auditoría inicial

Matriz completa: [01-auditoria-inicial.md](01-auditoria-inicial.md).

- **Vulnerabilidades confirmadas**: DG-01 (sin manifests → PASS, fallo
  abierto, HIGH), DG-04 (anidamiento hostil abortaba el análisis, MEDIUM),
  DG-05 (dependencias de desarrollo web con avisos, HIGH).
- **Funcionalidad incompleta**: DG-02/DG-03 (ecosistemas ignorados en
  silencio), DG-07/DG-08 (sin última versión ni estado de parche), DG-09
  (sin respaldo de severidad), DG-10 (sin ejecución local con interfaz),
  DG-12 (sin SPDX).
- **Deficiencias de proceso**: DG-06 (dependencias de CI sin fijar), DG-11
  (sin secretos, SCA independiente ni DAST en el pipeline).
- **Controles existentes conservados**: sin ejecución de código, symlinks no
  seguidos, HTTP con allowlist, fallo cerrado ante errores de red, saneado de
  texto, Actions fijadas por SHA, Trusted Publishing y procedencia SLSA.

## B. Modificaciones

Diez commits en `Beta`, sin push (decisión del propietario):

| Commit | Contenido |
|---|---|
| `428c00a` | DG-01, DG-04, DG-05 + informe de auditoría |
| `32859c7` | 10 adaptadores nuevos (pnpm, yarn, Pipfile.lock, pyproject, Cargo, Go, Composer, NuGet, Maven, Gradle), `safe_formats`, archivos reconocidos sin adaptador |
| `c740126` | Estado de parche, registros oficiales, NVD, saltos de versión mayor, campos nuevos del informe (ambos motores) |
| `91cd069` | SPDX 2.3, validación contra esquemas oficiales, fuente de CVSS en CycloneDX |
| `728c794` | Aplicación local `depguard serve` + interfaz React + tabla de dependencias |
| `1223de0` | `security.yml`, lock con hashes, job de empaquetado y e2e local, documentación DevSecOps |
| `c722e9c` | Versión posterior a la última estable nunca es «actualizada»; pruebas adversariales |
| `3747457` | Brechas ASVS: caducidad y cierre de sesión, registro de seguridad, charset |
| (docs) | Matrices ASVS/SSDF/SAMM/ISO, registro de vulnerabilidades, informes |

**Archivos creados** (principales): `dep_guard/adapters/{safe_formats,js_locks,python_manifests,rust_go_php,dotnet_jvm}.py`,
`dep_guard/{patch.py}`, `dep_guard/sources/{registries,nvd}.py`,
`dep_guard/reporters/spdx.py`, `dep_guard/server/{__init__,app,security,history}.py`,
`web/src/local/*`, `web/src/components/Dependencies.jsx`, `web/src/core/patch.js`,
`web/local.html`, `web/vite.local.config.js`, `web/playwright.local.config.js`,
`web/e2e-local/local.spec.js`, `.github/workflows/security.yml`,
`.zap/plan.yaml`, `requirements/{ci.txt,build.in}`,
`scripts/{validate_sbom,zap_plan}.py`, `fixtures/ecosystems/*` (25 archivos),
`tests/{test_ecosystems,test_patch_sources,test_spdx,test_server,test_adversarial}.py`,
`docs/{devsecops.md,security/excepciones.md,audit/*,compliance/*}`.

**Archivos modificados** (principales): `engine.py`, `policy.py`, `config.py`,
`discovery.py`, `models.py`, `correlate.py`, `cli.py`, `sources/http.py`,
reporters JSON/tabla/CycloneDX, motor JS (`policy.js`, `engine.js`,
`correlate.js`, `models.js`, `config.js`, `report.js`), `Results.jsx`,
`labels.js`, `web/package-lock.json`, `ci.yml`, `release.yml`,
`pyproject.toml`, `.gitignore`, goldens, documentación.

**Archivos eliminados**: ninguno.

**Cambios arquitectónicos**: aplicación local opcional (FastAPI, extra `web`)
con interfaz empaquetada en el wheel; nueva dependencia de ejecución PyYAML
(lockfiles YAML); el contrato de paridad Python↔JS pasa a cubrir solo el
comportamiento compartido (decisión del propietario).

## C. Funcionalidades implementadas

| Funcionalidad | Dónde | Verificación |
|---|---|---|
| Motor: 18 formatos, 7 ecosistemas | `dep_guard/adapters/` | `test_ecosystems.py`; lockfiles reales; OSV-Scanner 19/19 y 7/7 |
| Fuentes: OSV, NVD, KEV, EPSS, 7 registros | `dep_guard/sources/` | `test_patch_sources.py`, `test_resilience.py` |
| Verificación de parches (7 estados, última versión segura, salto mayor) | `dep_guard/patch.py`, `web/src/core/patch.js` | goldens + `test_patch_sources.py` |
| Interfaz web local | `dep_guard/server/`, `web/src/local/` | 57 tests de API, 4 e2e, DAST |
| Exportación JSON/SARIF/CycloneDX/SPDX | `dep_guard/reporters/`, API | esquemas oficiales, e2e |
| SBOM del propio DepGuard y de proyectos | `depguard sbom`, `security.yml`, `release.yml` | `validate_sbom.py` |
| Pipeline DevSecOps | `.github/workflows/` | actionlint; cada etapa ejecutada en local (ver D) |

## D. Validación

Detalle y comandos: [03-informe-pruebas.md](03-informe-pruebas.md).

| Herramienta | Resultado |
|---|---|
| pytest | 316 superadas, 2 omitidas (symlinks en Windows), cobertura 88,18 % |
| vitest | 139 superadas |
| Playwright | demo 20/20, app local 4/4 |
| ruff, mypy `--strict`, eslint, bandit | 0 hallazgos |
| gitleaks | 0 en 26 commits |
| OSV-Scanner, npm audit, DepGuard | 0 vulnerabilidades en las dependencias propias |
| Esquemas SPDX 2.3 / CycloneDX 1.6 | 0 violaciones (17 proyectos) |
| OWASP ZAP 2.17 autenticado | 0 alertas High/Medium/Low |
| actionlint | 0 errores |

**Pruebas fallidas y corregidas**: 7 (ver informe de pruebas §6), entre ellas
defectos reales DV-01, DV-02, DV-03 y DV-05 detectados por las propias
pruebas.

## E. Seguridad

- **Corregidas**: DG-01, DG-04, DG-05, DV-01…DV-07 y las brechas ASVS del
  commit `3747457` ([02-registro-vulnerabilidades.md](02-registro-vulnerabilidades.md)).
- **Controles implementados**: ver [../security.md](../security.md) (motor,
  red, app local, datos, criptografía, registro).
- **Riesgos residuales**: RR-01…RR-06 en
  [../security/excepciones.md](../security/excepciones.md) (caché local,
  ACL en Windows, hilo no interrumpible, TOCTOU con enlaces, logs sin
  protección, token en el historial del navegador).
- **Limitaciones**: [../limitations.md](../limitations.md).

## F. Evaluación de estándares

| Estándar | Nivel de cumplimiento real | Pendiente |
|---|---|---|
| OWASP ASVS 5.0 (L2) | 107/114 L1+L2 aplicables; 6 parciales; V16.4.2 no cumplido | Smuggling (V4.2.1), protección de logs, intercambio del token por código de un solo uso |
| NIST SSDF | 14/19 cumplidas, 4 parciales, 1 pendiente de verificar | Revisión por pares, configuración de GitHub |
| OWASP SAMM | 1,7 / 3 | Formación, incidentes, evaluación independiente |
| ISO/IEC 27001 | Apoya controles 5.7, 5.21, 8.8, 8.25–8.29… | Solo certificable un SGSI de una organización |

Detalle: [../compliance/](../compliance/).

## G. Estado de entrega

| Objetivo | Estado | Evidencia |
|---|---|---|
| Auditoría inicial | COMPLETADO | `docs/audit/01-auditoria-inicial.md` |
| Corrección de vulnerabilidades | COMPLETADO | `02-registro-vulnerabilidades.md`; regresiones en `tests/` |
| Análisis de dependencias | COMPLETADO | 18 formatos; `test_ecosystems.py`; validación cruzada con OSV-Scanner |
| Análisis de parches | COMPLETADO | `dep_guard/patch.py`; `test_patch_sources.py` |
| Interfaz local | COMPLETADO | `depguard serve`; e2e 4/4; wheel instalado sirve la UI |
| Seguridad de aplicación | PARCIAL | ASVS L2: 107/114; V16.4.2 y 6 parciales documentados |
| Pipeline DevSecOps | PARCIAL | Workflows completos y validados con actionlint, etapas ejecutadas en local; **sin ejecución en GitHub Actions** hasta el primer push |
| Pruebas funcionales | COMPLETADO | `03-informe-pruebas.md` §3 |
| Pruebas de seguridad | PARCIAL | SAST, SCA, secretos, DAST, adversariales completados; faltan pentest manual, fuzzing y pruebas de smuggling |
| SBOM | COMPLETADO | CycloneDX + SPDX validados; SBOM propio en CI y release |
| Documentación | COMPLETADO | README, `docs/`, SECURITY, CONTRIBUTING, CHANGELOG |
| Evaluación de estándares | COMPLETADO | `docs/compliance/` (evaluación interna) |
| Preparación para evaluación externa | PARCIAL | Evidencias y matrices listas; faltan pentest, revisión independiente y configuración de GitHub |

## Acciones pendientes del propietario

1. Revisar los commits de `Beta` y hacer push; comprobar la primera ejecución
   de `ci.yml` y `security.yml` (artefactos como evidencia).
2. Configurar en GitHub: protección de `Principal`, revisiones obligatorias,
   2FA, *private vulnerability reporting*; el Trusted Publisher de PyPI
   (pendiente desde la versión anterior).
3. Encargar una prueba de penetración independiente de `depguard serve`.
