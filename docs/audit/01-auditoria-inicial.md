# Auditoría inicial — DEPS-GUARD (DepGuard)

- Fecha: 2026-11-18
- Rama auditada: `Beta`, commit `9cb8b56` (release 1.0.0b2)
- Alcance: todo el repositorio (paquete Python `dep_guard/`, demo web `web/`,
  workflows de GitHub Actions, configuración y documentación).
- Método: lectura del código, ejecución de la batería existente y
  reproducción de cada hallazgo con evidencia. Ningún hallazgo se declara sin
  reproducción o sin una referencia concreta al código.

## 1. Estado real del proyecto

| Aspecto | Estado verificado |
|---|---|
| Lenguajes | Python 3.11+ (motor y CLI), JavaScript/React 19 (demo web, port del motor) |
| Dependencias de ejecución (Python) | `httpx`, `rich`, `packaging` |
| Punto de entrada | `depguard` → `dep_guard.cli:main`; `python -m dep_guard` |
| Arquitectura | Pipeline `discover → parse → OSV querybatch → detalles → correlación → EPSS/KEV → riesgo → política → reporters` (`dep_guard/engine.py`) |
| Formatos soportados | `package-lock.json`/`npm-shrinkwrap.json` v2–v3, `package.json`, `poetry.lock`, `uv.lock`, `requirements*.txt`, CycloneDX JSON |
| Fuentes | OSV.dev (estado de vulnerabilidad), FIRST EPSS y CISA KEV (enriquecimiento) |
| Salidas | Tabla, JSON (`depguard.report/v1`), SARIF 2.1.0, CycloneDX 1.6 |
| Pruebas | pytest: 170 superadas, 1 omitida (symlinks en Windows); vitest: 137 superadas |
| Análisis estático | ruff (reglas `S`), mypy `--strict`, bandit: sin hallazgos |
| CI | `ci.yml` (matriz Python 3.11–3.14 + Windows, auto-escaneo con SARIF, demo web + e2e, dependency-review), `codeql.yml`, `scorecard.yml`, `release.yml` (Trusted Publishing, procedencia SLSA, SBOM, SHA256SUMS) |
| Interfaz | Solo la demo pública en navegador (motor JS); no existe ejecución local con interfaz web |

Implementado de verdad: todo lo anterior, con pruebas. Documentado pero
pendiente de acciones del propietario: despliegue en Netlify y el trusted
publisher de PyPI (ver `docs/releasing.md`).

## 2. Matriz de hallazgos

Tipos: **V** vulnerabilidad confirmada · **R** riesgo potencial · **F** error
funcional · **M** mejora recomendada.

| ID | Tipo | Hallazgo | Severidad | Archivo | Impacto | Solución |
|---|---|---|---|---|---|---|
| DG-01 | F | Un directorio sin manifiestos soportados devuelve **PASS** (exit 0). Reproducido: carpeta con solo `pyproject.toml` que fija `requests==2.19.0` → "Política: PASS. No se encontraron vulnerabilidades conocidas". | HIGH | `dep_guard/policy.py` (`evaluate`), `dep_guard/engine.py` | Falso negativo silencioso: en CI un repositorio con un ecosistema no soportado pasa la puerta de seguridad. Es *fail-open*. | Sin manifiestos analizados → veredicto `INCOMPLETE` (exit 3) y problema explícito. Mismo cambio en el motor JS (comportamiento compartido). |
| DG-02 | F | `pyproject.toml` (PEP 621 `[project.dependencies]`, `[project.optional-dependencies]`, `[dependency-groups]`, Poetry sin lock) no se analiza. | HIGH | `dep_guard/adapters/__init__.py` | Proyectos Python modernos sin lockfile quedan sin analizar (agravado por DG-01). | Adaptador `pyproject` (directas; versiones exactas consultadas, rangos `unresolved`), sustituido por `poetry.lock`/`uv.lock` cuando existen. |
| DG-03 | F | Ecosistemas sin adaptador: pnpm, yarn (v1 y Berry), `Pipfile.lock`, Cargo, Go, Composer, Maven (`pom.xml`), Gradle (lockfile), NuGet (`packages.lock.json`, `.csproj`). Los archivos se ignoran sin aviso. | MEDIUM | `dep_guard/adapters/` | Cobertura parcial con apariencia de completa. | Un adaptador específico por formato, con fixtures y pruebas propias. Formatos que exigen ejecutar el gestor (scripts Gradle, POM padre remoto) se reportan como limitación, no se adivinan. |
| DG-04 | V | JSON con anidamiento profundo provoca `RecursionError` no controlado: aborta el escaneo completo ("internal error", exit 2) en lugar de marcar ese archivo como corrupto. | MEDIUM | `dep_guard/engine.py` (`parse_files`), adaptadores JSON | Denegación de servicio de un escaneo con un archivo hostil; en un servidor local sería un error 500 por petición. Falla cerrado (nunca PASS). | Capturar `RecursionError`/`MemoryError` del parser como `ParseError`; prueba de regresión. |
| DG-05 | V | Dependencias de desarrollo de `web/` con avisos publicados: `vite` 8.3.2 (launch-editor: ejecución de comandos en Windows, lectura de archivos fuera de la raíz del dev server), `undici` 8.11.2 (8 avisos), `zod` 4.6.5, `minimatch` 10.2.6, `picomatch`/`tinyglobby`/`fdir` (ReDoS vía vitest). Confirmado con `npm audit` y con el auto-escaneo de DepGuard. | HIGH (herramientas de desarrollo; no forman parte del bundle publicado) | `web/package-lock.json` | Compromiso del equipo de un desarrollador al usar el dev server; no afecta al sitio estático publicado. | Actualizar a versiones corregidas; añadir `npm audit` como puerta en CI. |
| DG-06 | R | Dependencias de CI/desarrollo Python sin fijar (`pip install -e ".[dev]"` con rangos `>=`; `pip install build` sin versión en `release.yml`). | MEDIUM | `pyproject.toml`, `.github/workflows/*.yml` | Builds no reproducibles; una versión comprometida de una herramienta se ejecutaría en CI. | Archivo de restricciones con versiones exactas y hashes para CI y release (`--require-hashes`). |
| DG-07 | F | No se determina la última versión publicada: imposible distinguir "actualizada" de "desactualizada sin vulnerabilidades". | MEDIUM | `dep_guard/sources/` | No cubre los estados 1–2 de la verificación de parches. | Consultas a las APIs oficiales de cada registro (PyPI JSON, npm registry, crates.io, proxy.golang.org, Packagist, Maven Central, NuGet), con caché y allowlist de hosts. |
| DG-08 | F | No se clasifica el estado de parche por dependencia (actualizada / desactualizada / vulnerable con parche / sin parche / sin datos / versión no identificable). | MEDIUM | `dep_guard/models.py`, reporters | El usuario debe inferir el estado combinando campos. | Campo `patch_status` calculado y explicado por componente. |
| DG-09 | F | CVSS v4 no se puntúa y no hay fuente alternativa cuando OSV no trae vector (p. ej. `CVE-2026-112943` sin puntuación en el auto-escaneo). CWE solo desde `database_specific` de GHSA. | LOW | `dep_guard/correlate.py`, `dep_guard/cvss.py` | Severidad `UNKNOWN` o solo cualitativa en algunos avisos. | Enriquecimiento opcional con NVD API 2.0 (CVSS v3.x/v4.0 y CWE) para CVE sin vector, con límite de tasa documentado. |
| DG-10 | M | No existe ejecución local con interfaz web; la demo pública depende de un despliegue en Netlify no conectado. | MEDIUM | — | Para usar la UI hay que clonar el repo y usar npm. | `depguard serve`: FastAPI en 127.0.0.1 + UI React empaquetada en el wheel (extra `devs-guard[web]`). |
| DG-11 | M | Pipeline sin secret scanning, sin segunda opinión SCA (OSV-Scanner/pip-audit), sin Semgrep y sin DAST. | MEDIUM | `.github/workflows/` | Detección tardía de secretos y de fallos del propio escáner. | Jobs nuevos con acciones fijadas por SHA, permisos mínimos y evidencias como artefactos. |
| DG-12 | M | SBOM solo en CycloneDX; sin SPDX; el SBOM de release no incluye la UI. | LOW | `dep_guard/reporters/` | Interoperabilidad limitada con herramientas que exigen SPDX. | Reporter SPDX 2.3 JSON (`--format spdx`, `depguard sbom --format spdx`). |
| DG-13 | R | Integridad: los hashes de `requirements.txt` (`--hash`) y `integrity` de `package-lock.json` se ignoran. | LOW | adaptadores | No se detecta un lockfile manipulado. | Comprobación opcional del hash del lockfile contra los metadatos oficiales del registro (sin descargar paquetes). |
| DG-14 | R | La caché local (JSON en `%LOCALAPPDATA%`) la puede modificar cualquier proceso del mismo usuario; `0o700` no aplica en Windows. | LOW | `dep_guard/sources/cache.py` | Envenenamiento de caché requiere ya acceso local como el usuario. | Riesgo residual documentado; `--no-cache` disponible. |
| DG-15 | M | Pasos de resumen en CI y `action.yml` terminan con `|| true`. | INFORMATIONAL | `ci.yml`, `action.yml` | No ocultan la puerta (el paso que decide es otro), pero conviene dejarlo explícito. | Comentario que lo justifica; la puerta conserva su código de salida. |
| DG-16 | M | GitHub Security Advisories y NVD no se consultan directamente. | INFORMATIONAL | `dep_guard/sources/` | OSV ya ingiere GHSA y referencia CVE; consultar GHSA aparte duplicaría datos y exige token. | Documentar la decisión; NVD solo como enriquecimiento (DG-09). |
| DG-17 | R | La prueba de symlinks se omite en Windows (requiere privilegios). | INFORMATIONAL | `tests/test_security.py` | Cubierta en Linux CI. | Sin cambio; documentado. |

## 3. Controles existentes que se conservan

- No hay `subprocess`, `eval`, `exec` ni `pickle` en el paquete (prueba `test_no_code_execution_primitives_in_package`).
- No se siguen enlaces simbólicos; límites de 25 MB por archivo, 1000 manifiestos y profundidad 12.
- HTTP: solo HTTPS a hosts en allowlist, sin redirecciones, respuesta con tamaño máximo, reintentos con backoff.
- "No se pudo comprobar" nunca es "sin vulnerabilidades": veredicto `INCOMPLETE`/exit 3.
- Texto externo saneado (ANSI, bidi, ancho cero) antes de imprimirse.
- Actions fijadas por SHA, `permissions: contents: read`, `persist-credentials: false`, Trusted Publishing, procedencia SLSA.

## 4. Plan de intervención

| Fase | Trabajo | Hallazgos |
|---|---|---|
| 3 | Correcciones críticas/altas: fail-open sin manifiestos (Python + JS), `RecursionError`, dependencias web vulnerables | DG-01, DG-04, DG-05 |
| 4 | Motor: adaptadores `pyproject`, `Pipfile.lock`, pnpm, yarn, Cargo, Go, Composer, Maven, Gradle, NuGet; última versión por registro; `patch_status`; NVD; SPDX | DG-02, DG-03, DG-07, DG-08, DG-09, DG-12 |
| 5–6 | `depguard serve` (FastAPI, 127.0.0.1, token, Host/Origin, raíces permitidas, CSP) + UI React local | DG-10 |
| 7 | Pipeline: Gitleaks, OSV-Scanner, pip-audit, Semgrep, `npm audit`, DAST ZAP contra `depguard serve`, restricciones con hashes | DG-06, DG-11 |
| 8–10 | Pruebas adversariales, matrices ASVS/SSDF/SAMM/ISO 27001, informe de conformidad, README | — |

Decisiones del propietario (2026-11-18): backend FastAPI + uvicorn como extra
opcional; UI local reutilizando React/Vite; los nuevos ecosistemas solo en el
motor Python (la demo JS conserva su subconjunto y los goldens compartidos no
cambian salvo por correcciones de comportamiento común); un commit por fase en
`Beta`, sin push.
