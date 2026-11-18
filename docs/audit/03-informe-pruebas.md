# Informe de pruebas

- Fecha de la ejecución final: 2026-11-18, rama `Beta`.
- Entorno: Windows 11, Python 3.13.14, Node 24.16.0, Java 21 (ZAP), Chromium
  de Playwright. Herramientas externas verificadas por SHA-256 frente a su
  publicación oficial: gitleaks 8.30.1, OSV-Scanner 2.7.0, OWASP ZAP 2.17.0.
- Todas las cifras de este documento salen de ejecuciones reales; las salidas
  se reproducen con los comandos indicados.

## 1. Resumen

| Batería | Herramienta | Resultado | Comando |
|---|---|---|---|
| Unitarias, integración, seguridad, adversariales (Python) | pytest | **316 superadas**, 2 omitidas, 0 fallidas; cobertura **88,18 %** (mínimo 85 %) | `pytest --cov` |
| Unitarias + paridad + suite de calidad (JS) | vitest | **139 superadas** | `cd web && npm test` |
| E2E demo pública (escritorio y móvil, bajo CSP de producción) | Playwright | **20/20** | `cd web && npx playwright test` |
| E2E aplicación local contra `depguard serve` real | Playwright | **4/4** | `npx playwright test -c playwright.local.config.js` |
| Lint y tipos | ruff, mypy `--strict`, eslint | 0 problemas (44 módulos tipados) | ver `ci.yml` |
| SAST | bandit | 0 hallazgos en 6010 líneas; 6 supresiones `nosec` justificadas en el código | `bandit -c pyproject.toml -r dep_guard` |
| Secretos | gitleaks (historial completo) | 0 hallazgos en 26 commits | `gitleaks git . --redact` |
| SCA propio | DepGuard (autoescaneo) | PASS, 0 hallazgos | `depguard scan .` |
| SCA segunda opinión | OSV-Scanner | 0 vulnerabilidades en 281 paquetes npm y 50 PyPI | `osv-scanner scan source -L …` |
| SCA npm | npm audit | 0 vulnerabilidades | `npm audit` |
| SBOM | `scripts/validate_sbom.py` | 0 violaciones: 17 proyectos × (SPDX 2.3 + CycloneDX 1.6) contra los esquemas oficiales | ver `security.yml` |
| DAST | OWASP ZAP 2.17 (spider, pasivo, activo autenticado) | 0 alertas High/Medium/Low; 3 informativas revisadas | `.zap/plan.yaml` + `scripts/zap_plan.py` |
| Workflows | actionlint 1.7.12 | 0 errores en 5 workflows | `actionlint .github/workflows/*.yml` |
| Caracteres invisibles | `check_text_safety.py` | ok | — |

## 2. Validación cruzada con una implementación independiente

DepGuard y OSV-Scanner 2.7.0 analizaron los mismos lockfiles reales
(proyectos del propietario, solo lectura, sin copiarlos al repositorio):

| Lockfile | Paquetes (DepGuard / OSV-Scanner) | Avisos (DepGuard / OSV-Scanner) | Diferencias |
|---|---|---|---|
| `web/package-lock.json` (este repo) | 281 / 281 | 0 / 0 | ninguna |
| `requirements/ci.txt` (este repo) | 50 / 50 | 0 / 0 | ninguna |
| `pnpm-lock.yaml` v9 (monorepo real) | — | 19 / 19 | ninguna en ningún sentido |
| `Cargo.lock` (aplicación Tauri real) | — | 7 / 7 | ninguna en ningún sentido |

Parseo de archivos reales adicionales: `pnpm-lock.yaml` (674 y 189
paquetes), `Cargo.lock` (444 crates), `pom.xml` (11 dependencias, 8 heredadas
de un POM padre marcadas como no resueltas) y `.csproj` (5 referencias).

## 3. Casos de prueba funcionales

| Caso | Resultado esperado | Resultado obtenido | Evidencia | Estado |
|---|---|---|---|---|
| Detección de manifests en 16 formatos | Cada formato con su adaptador | Inventario exacto por fixture | `test_adapter_output_is_exactly_the_expected_inventory` (14 fixtures) | Aprobado |
| Lockfile sustituye a su manifest | `package.json`/`composer.json`/`.csproj`/`Cargo.toml`/`Pipfile` no se duplican | No se analizan si hay lockfile | `test_lockfile_supersedes_its_manifest` | Aprobado |
| Dependencias directas y transitivas | Directa/transitiva y ruta desde la dependencia directa | p. ej. `react-dom › loose-envify › js-tokens` | `test_transitive_paths_explain_why_a_package_is_installed` | Aprobado |
| Ámbito prod/dev | Según el formato (flags npm, `packages-dev`, grupos, `test` en Maven) | Correcto en todos los fixtures | `tests/test_ecosystems.py` | Aprobado |
| `replace` de Go | Se analiza el módulo que se compila | `github.com/new/lib`, no `old/lib` | `test_go_replace_scans_the_module_that_is_actually_built` | Aprobado |
| Comparación de versiones | Tablas compartidas Python/JS | Paridad | `fixtures/golden/versions.json` | Aprobado |
| Consulta de vulnerabilidades | OSV en lote, detalles por id, caché | Goldens idénticos en ambos motores | `test_report_matches_golden`, `parity.test.js` | Aprobado |
| Identificación de parches (7 estados) | Cada estado con su explicación | Correcto | `test_every_patch_state_with_its_reason` | Aprobado |
| "Última publicada" ≠ "última segura" | Si la última versión también está afectada, se dice | "la última versión 6.9.0 también está afectada" | `test_latest_published_is_not_latest_safe`, `test_scan_with_latest_distinguishes_every_state` | Aprobado |
| Actualización incompatible | Salto mayor (o 0.x menor) señalado | `0.5.0 → 0.7.0` marcado | `test_breaking_upgrade_detection` | Aprobado |
| Última versión estable por registro | PyPI, npm, crates.io, Go, Packagist, Maven, NuGet; sin pre-releases ni yanked | Correcto | `test_latest_stable_release_per_registry` | Aprobado |
| NVD como respaldo | Solo avisos sin CVSS; v3.1 primaria puntuada localmente; v4 de NVD; CWE | Correcto | `test_nvd_*` | Aprobado |
| Generación de informes | JSON, SARIF, CycloneDX, SPDX | Válidos (esquemas oficiales) | `tests/test_cli_reporters.py`, `tests/test_spdx.py`, `validate_sbom.py` | Aprobado |
| Errores de APIs | 429/5xx/timeout/JSON inválido → `INCOMPLETE` | Correcto | `tests/test_resilience.py`, `core.test.js` | Aprobado |
| Ejecución local | `depguard serve` sirve la UI desde el wheel instalado | 200 en `/` y en los assets desde `site-packages` | prueba manual con wheel en venv limpio | Aprobado |
| Selección de carpetas | Navegador de carpetas dentro de las raíces | Correcto | e2e `scan a project: picker…` | Aprobado |
| Historial | Guardar, abrir, borrar | Correcto | `test_scan_history_and_exports`, e2e | Aprobado |
| Exportación | 4 formatos con nombre fijo y `attachment` | Correcto | `test_scan_history_and_exports`, e2e (SPDX) | Aprobado |
| Instalación reproducible | Lock con hashes en venv limpio → 316 tests | Correcto | prueba en venv limpio | Aprobado |

## 4. Pruebas negativas y adversariales

| Caso | Resultado esperado | Obtenido | Evidencia | Estado |
|---|---|---|---|---|
| Dependencias vulnerables conocidas | Detectadas con prioridad | Log4Shell P0 + KEV, 60 avisos de jackson-databind | escaneo en vivo de `fixtures/ecosystems/maven` | Aprobado |
| Dependencias seguras | Sin hallazgos | 0 en los lockfiles del repo | autoescaneo | Aprobado |
| Versiones inexistentes | Nunca "limpia" ni "actualizada" | `INCOMPLETE` sin conexión; "pre-release o no publicada" con registro | `test_nonexistent_version_is_never_reported_clean_offline` | Aprobado |
| Manifests corruptos | `ParseError` por archivo; resto analizado | Correcto (11 formatos) | `test_malformed_files_raise_parse_error` | Aprobado |
| Lockfiles incompletos | Sin inventar datos | Referencias rotas ignoradas | `test_incomplete_lockfiles_degrade_without_inventing_data` | Aprobado |
| Nombres ambiguos | `Django`=`django`, `zope.interface`=`Zope_Interface`; `@types/node` ≠ `types-node` | Correcto | `test_ambiguous_python_names_are_one_package`, `test_npm_scoped_and_lookalike_names_stay_distinct` | Aprobado |
| Archivos excesivamente grandes | Rechazados (> 25 MB) | Correcto | `test_oversized_file_is_refused` | Aprobado |
| Anidamiento hostil | Solo invalida ese archivo | Correcto | `test_hostile_nesting_*` | Aprobado |
| YAML "billion laughs" | Rechazado antes de expandir | Correcto | `test_yaml_alias_bomb_is_refused_before_expansion` | Aprobado |
| XXE / expansión de entidades | Rechazado | Correcto (3 variantes × 3 formatos) | `test_xml_with_dtd_is_refused` | Aprobado |
| Rutas manipuladas | `..`, relativas, UNC, NUL, > 4096, inexistentes → 403/422 | Correcto | `test_paths_outside_the_allowed_roots_are_refused` | Aprobado |
| UNC sin tocar el disco | Rechazo léxico previo a `resolve()` | Correcto | `test_unc_paths_are_refused_before_touching_the_file_system` | Aprobado |
| Symlinks que salen de la raíz | No se siguen / 403 | Omitido en Windows (privilegios); cubierto en CI Linux | `test_symlinks_are_not_followed`, `test_symlink_escape_is_refused` | **Pendiente de ejecución en Linux** |
| Fuentes no disponibles | `INCOMPLETE`, nunca PASS | Correcto | `tests/test_resilience.py`, `test_not_found_and_failures_are_reported_never_guessed`, `test_nvd_outage_keeps_osv_severity` | Aprobado |
| No ejecuta código del proyecto | `preinstall`, `setup.py`, `conftest.py` no se ejecutan; nada se escribe | Correcto | `test_scanned_projects_are_never_executed`, `test_no_code_execution_primitives_in_package` | Aprobado |
| Prototype pollution (motor JS) | Claves `__proto__` inertes | Correcto | `untrusted keys never pollute prototypes` | Aprobado |
| Nombres hostiles (ANSI, bidi) | Saneados | Correcto | `test_hostile_names_are_sanitised` | Aprobado |

## 5. Pruebas de seguridad de la aplicación local

| Control | Prueba | Resultado |
|---|---|---|
| Autenticación | sin token / token erróneo / sin `Bearer` → 401 | Aprobado |
| DNS rebinding | 5 valores de `Host` → 400 | Aprobado |
| Origen | 4 orígenes ajenos → 403; mismo origen → 200 | Aprobado |
| Fetch metadata | `Sec-Fetch-Site: cross-site` → 403 | Aprobado |
| CORS | preflight ajeno sin `Access-Control-Allow-Origin` | Aprobado |
| Validación estricta | 8 cuerpos inválidos → 422; > 16 KB → 413 | Aprobado |
| Concurrencia y timeout | 409 si ocupado; 504 y bloqueo mantenido | Aprobado |
| Errores | 500 sin detalles internos | Aprobado |
| Sesión | inactividad, caducidad absoluta, cierre de sesión | Aprobado |
| Registro | eventos sin token y sin inyección | Aprobado |
| Cabeceras | CSP, nosniff, Referrer-Policy, XFO, COOP, CORP, `no-store` | Aprobado |
| Métodos | TRACE/PUT/PATCH/CONNECT → 405; `/docs` → 404 | Aprobado |
| Enlace de red | socket en `127.0.0.1` | Aprobado (`netstat`: solo `127.0.0.1:<puerto>` en LISTEN) |
| Caja negra (servidor real, curl) | sin token, rebinding, origen, preflight, OpenAPI, ruta externa, traversal, UNC | Aprobado (401/400/403/0 cabeceras CORS/404/403/403/403) |

### DAST (OWASP ZAP 2.17.0)

Spider, escaneo pasivo y activo (fuerza media) autenticados contra
`depguard serve` con `fixtures/` como raíz. Durante el escaneo activo ZAP lanzó
21 análisis con cuerpos manipulados; los 21 quedaron dentro de la raíz
permitida (comprobado en el historial aislado).

| Alerta | Riesgo | Instancias | Revisión |
|---|---|---|---|
| 10027 Information Disclosure – Suspicious Comments | Informativo | 1 (bundle JS) | Comentarios de librerías minificadas |
| 10109 Modern Web Application | Informativo | 2 | SPA |
| 10104 User Agent Fuzzer | Informativo | 3 | Las respuestas no cambian con el User-Agent |

Sin alertas High, Medium ni Low. Las dos primeras ejecuciones se descartaron
porque ZAP no enviaba el token (ver `02-registro-vulnerabilidades.md`).

## 6. Pruebas fallidas durante el desarrollo y su corrección

| Prueba | Causa | Corrección |
|---|---|---|
| `test_adapter_output…[yarn-berry]` | nombre `typescript@patch:typescript` | DV-03 |
| `test_slow_scans_time_out…` | bloqueo liberado por el callback del futuro | DV-01 |
| `test_session_has_an_absolute_lifetime` | `0.0 or now` | DV-02 |
| `test_adapter_output…[nuget-lock]` | ámbito `prod` sin datos para afirmarlo | `unknown` |
| `test_maven_property_cycles_terminate` | `child_text(None)` | aceptar `None` |
| e2e `a path outside…` | la ruta de prueba era relativa por un escape; pasaba por el motivo equivocado | prueba con ruta absoluta y mensaje exacto |
| Wheel sin interfaz | `artifacts` solo en el objetivo wheel | DV-05 |

## 7. Lo que no se ha ejecutado

| Prueba | Motivo | Cómo se cubrirá |
|---|---|---|
| Workflows en GitHub Actions (`ci.yml`, `security.yml`, `release.yml`) | No se ha hecho push (decisión del propietario: commits sin push) | Primera ejecución al publicar la rama; validados con actionlint |
| Symlinks (2 tests) | Windows exige privilegios para crearlos | Job Linux de `ci.yml` |
| Matriz Python 3.11, 3.12, 3.14 y Linux | Solo Python 3.13 en Windows en local | `ci.yml` |
| Request smuggling (ASVS V4.2.1) | Sin herramienta específica | Pendiente (acción en `asvs-5.0.md`) |
| Fuzzing de parsers y ReDoS | No implementado | Pendiente (acción en `asvs-5.0.md`) |
| Prueba de penetración manual | Requiere un evaluador independiente | Ver `docs/compliance/informe-conformidad.md` |
