# 🛡️ DepGuard (DEPS-GUARD)

[![CI](https://github.com/AlejandroDukesini/Devs-Guard/actions/workflows/ci.yml/badge.svg)](https://github.com/AlejandroDukesini/Devs-Guard/actions/workflows/ci.yml)
[![Security](https://github.com/AlejandroDukesini/Devs-Guard/actions/workflows/security.yml/badge.svg)](https://github.com/AlejandroDukesini/Devs-Guard/actions/workflows/security.yml)
[![CodeQL](https://github.com/AlejandroDukesini/Devs-Guard/actions/workflows/codeql.yml/badge.svg)](https://github.com/AlejandroDukesini/Devs-Guard/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/AlejandroDukesini/Devs-Guard/badge)](https://scorecard.dev/viewer/?uri=github.com/AlejandroDukesini/Devs-Guard)
[![Python](https://img.shields.io/badge/python-3.11%E2%80%933.14-blue.svg)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**Analizador de dependencias y vulnerabilidades que explica qué arreglar
primero, si existe parche y por qué — desde la terminal, en CI o en una
interfaz web local.**

## 1. Objetivo y problema que resuelve

Un proyecto moderno instala cientos de paquetes de terceros. Saber cuáles
tienen vulnerabilidades conocidas, cuáles tienen parche, cuál es la versión
mínima que lo corrige y si esa actualización rompe la compatibilidad suele
exigir varias herramientas y criterio manual. Además, muchas herramientas
responden "sin vulnerabilidades" cuando en realidad **no pudieron comprobar**
algo (red caída, formato no soportado).

DepGuard lee los lockfiles y manifests de tu proyecto (sin ejecutarlos),
consulta fuentes oficiales y entrega:

- el **estado de parche** de cada dependencia (actualizada, desactualizada,
  vulnerable con parche, vulnerable sin parche, sin datos, versión no
  identificable);
- una **prioridad explicada** (P0–P3) que combina CVSS, explotación activa
  (CISA KEV), probabilidad de explotación (EPSS) y contexto (producción o
  desarrollo, directa o transitiva);
- un **veredicto determinista** para CI: `PASS`, `FAIL` o `INCOMPLETE`
  ("no se pudo comprobar" nunca es "seguro").

## 2. Características

- 18 formatos de 7 ecosistemas nativos (npm, PyPI, crates.io, Go, Packagist,
  NuGet, Maven) + SBOM CycloneDX para el resto.
- Dependencias directas y transitivas, con la ruta que explica por qué está
  instalado cada paquete.
- Verificación de parches: versión mínima que corrige, última versión estable
  del registro oficial, y comprobación de si **esa** última versión también
  está afectada.
- Aviso de actualizaciones incompatibles (salto de versión mayor).
- Severidad CVSS v3 calculada localmente, respaldo de NVD (CVSS v3/v4, CWE).
- Excepciones auditables con motivo y caducidad obligatorios.
- Salidas: tabla, JSON, SARIF (GitHub code scanning), CycloneDX 1.6 (SBOM +
  VEX), SPDX 2.3.
- Aplicación web local (`depguard serve`): selector de carpetas, historial,
  dependencias y estado de parches, exportación.
- GitHub Action y librería de Python.

```text
$ depguard scan .
DepGuard 1.0.0b2
✓ 1 archivo(s) analizados: requirements.txt
✓ 3 dependencias (3 directas) · 1 sin versión exacta
✓ OSV: ok   ✓ EPSS: ok   ✓ KEV: ok

 Prio  Paquete    Vulnerabilidad        Severidad   Corrige en  Origen
 ──────────────────────────────────────────────────────────────────────────
 P1    flask      CVE-2023-30861        HIGH 7.5    2.2.5       directa · prod
       2.2.2      Flask vulnerable to…
 P2    requests   CVE-2023-32681        MEDIUM 6.1  2.31.0      directa · prod
       2.20.0     Unintended leak of …
 …
Por qué importan (P0/P1)
  P1 CVE-2023-30861 flask@2.2.2 — Flask vulnerable to possible disclosure of …
      EPSS 0.013 (percentil 69) · Severidad HIGH CVSS 7.5 · Dependencia de producción · …

Remediación sugerida
  • flask 2.2.2 → 3.1.3  corrige 2 de 2
  • requests 2.20.0 → 2.33.0  corrige 4 de 4

No analizadas por falta de versión exacta (1)
  urllib3: not pinned (>=1.25)

Resultado  P0 0  P1 1  P2 5  P3 0
Política: FAIL
```

<sub>Salida real de un escaneo del 2026-10-05 con la versión 1.0.0b2; los datos de OSV cambian a diario. Las versiones actuales añaden avisos de cambio de versión mayor y el estado de parche.</sub>

## 3. Arquitectura y tecnologías

```text
CLI · librería · app local (FastAPI en 127.0.0.1 + React)
                 │
          motor (Python 3.11+)
   descubrimiento → adaptadores → OSV → correlación → NVD/EPSS/KEV
   → última versión (registros) → riesgo → parches → política → informes
```

| Pieza | Tecnología |
|---|---|
| Motor y CLI | Python 3.11+ (`httpx`, `rich`, `packaging`, `PyYAML`) |
| App local | FastAPI + uvicorn (extra opcional `web`), interfaz React 19 + Vite + Tailwind |
| Demo pública | El motor portado a JavaScript, en el navegador ([web/](web/README.md)) |
| Pruebas | pytest, vitest, Playwright, OWASP ZAP |

Detalles: [docs/architecture.md](docs/architecture.md).

## 4. Instalación

Requiere Python 3.11 o superior.

```bash
pip install devs-guard              # CLI (cuando se publique en PyPI; el comando es `depguard`)
pip install "devs-guard[web]"       # + interfaz web local
# hasta la publicación, desde GitHub:
pip install "devs-guard[web] @ git+https://github.com/AlejandroDukesini/Devs-Guard@Beta"
```

> Instalar desde GitHub no incluye la interfaz compilada (se genera en la
> release). Desde un clon: `cd web && npm ci --ignore-scripts && npm run build:local`.

## 5. Ejecución local

### Interfaz web

```bash
depguard serve                      # abre http://127.0.0.1:8765/ en tu navegador
depguard serve --root ~/proyectos   # limita las carpetas que se pueden analizar
```

1. Elige la carpeta de tu proyecto (o pega su ruta).
2. Revisa las opciones (última versión, NVD, EPSS, KEV, sin conexión).
3. Pulsa **Analizar**: verás el veredicto, las vulnerabilidades priorizadas,
   el estado de parche de cada dependencia y la remediación sugerida.
4. Descarga el informe (JSON, SARIF, CycloneDX, SPDX). El historial guarda
   los últimos 50 análisis; «Cerrar sesión» revoca el acceso.

El servidor solo escucha en `127.0.0.1`, exige un token de sesión, rechaza
otras páginas web y nunca lee fuera de las carpetas permitidas.

### Línea de comandos

```bash
depguard scan .                          # directorio: encuentra lockfiles y manifests
depguard scan . --latest                 # + última versión estable y estado de parche
depguard scan . --nvd                    # + CVSS/CWE de NVD para avisos sin vector
depguard scan . -f sarif -o depguard.sarif
depguard scan . -f json  -o report.json
depguard scan . --fail-on P0             # solo falla con P0
depguard sbom . -o bom.cdx.json          # SBOM CycloneDX (sin consultar vulnerabilidades)
depguard sbom . -f spdx -o sbom.spdx.json
depguard formats                         # archivos soportados
```

| Exit code | Significado |
|---|---|
| `0` | PASS: política cumplida y todo comprobado |
| `1` | FAIL: política incumplida |
| `2` | Error de la herramienta (argumentos, ruta, configuración, fallo interno) |
| `3` | INCOMPLETE: algo no se pudo comprobar (red, formato no soportado, manifest corrupto, ningún manifest) |

Como librería:

```python
from dep_guard import scan
from dep_guard.engine import ScanOptions

report = scan("path/to/project", ScanOptions(latest=True))
print(report.policy.verdict, report.exit_code)
for c in report.components:
    print(c.name, c.version, c.patch_status, c.patch_note)
```

## 6. Ecosistemas compatibles

| Ecosistema | Archivos |
|---|---|
| npm | `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock` (1 y Berry), `package.json` |
| PyPI | `poetry.lock`, `uv.lock`, `Pipfile.lock`, `requirements*.txt`, `pyproject.toml` |
| Rust | `Cargo.lock` |
| Go | `go.mod` |
| PHP | `composer.lock`, `composer.json` |
| .NET | `packages.lock.json`, `*.csproj`/`*.fsproj`/`*.vbproj`, `Directory.Packages.props` |
| Java | `pom.xml` (directas), `gradle.lockfile` |
| Cualquiera con purl | SBOM CycloneDX JSON |

Los archivos reconocidos sin adaptador (`Gemfile.lock`, `Cargo.toml` sin
lock…) se avisan y hacen el resultado `INCOMPLETE`. Detalle:
[docs/ecosystems.md](docs/ecosystems.md).

## 7. Fuentes de vulnerabilidades

| Fuente | Uso |
|---|---|
| [OSV.dev](https://osv.dev) | Estado de vulnerabilidad (fuente de verdad); agrega GitHub Security Advisories, PyPA, RustSec, Go y CVE |
| [NVD](https://nvd.nist.gov/developers) | Respaldo de CVSS v3/v4 y CWE para avisos sin vector (`--nvd`) |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Explotación activa confirmada |
| [FIRST EPSS](https://www.first.org/epss/) | Probabilidad de explotación en 30 días |
| Registros oficiales | Última versión estable: PyPI, npm, crates.io, proxy de Go, Packagist, Maven Central, NuGet (`--latest`) |

Solo se usan APIs oficiales y documentadas; nunca *scraping*.

## 8. Metodología de análisis

1. Descubre manifests sin seguir enlaces simbólicos; un lockfile sustituye a
   su manifest.
2. Extrae versiones **exactas**; rangos, git o rutas locales quedan como
   «versión no identificable» con el motivo (nunca se adivina).
3. Consulta OSV con las versiones exactas; agrupa alias (CVE/GHSA/OSV) en un
   solo hallazgo; precedencia de severidad: vector CVSS > calificación del
   aviso > NVD > desconocida (nunca se asume baja).
4. Elige la versión corregida del rango afectado que contiene la instalada y
   la actualización mínima que corrige todos los avisos de un paquete.
5. Prioriza con una tabla de decisión explicable:

| Prioridad | Regla |
|---|---|
| **P0** | En producción **y** (en CISA KEV **o** EPSS ≥ 0.10 con severidad ≥ HIGH) |
| **P1** | Severidad ≥ HIGH en producción, **o** EPSS ≥ 0.10, **o** en KEV |
| **P2** | MEDIUM o severidad desconocida en producción; HIGH+ solo en desarrollo |
| **P3** | El resto |

La severidad técnica (CVSS) y el riesgo contextual (P0–P3) se muestran por
separado. Detalles: [docs/risk-model.md](docs/risk-model.md).

## 9. Seguridad y privacidad

- **Solo lectura**: no instala dependencias ni ejecuta scripts ni gestores
  de paquetes del proyecto analizado; no modifica ningún archivo.
- A las fuentes solo se envían ecosistema, nombre y versión.
  `private_packages` evita enviar paquetes internos; `--offline` no hace
  ninguna petición.
- Red: solo HTTPS, solo hosts en una lista cerrada, sin redirecciones.
- App local: `127.0.0.1`, token de 256 bits en cabecera, protección contra
  DNS rebinding y peticiones de otros orígenes, carpetas permitidas,
  caducidad de sesión, CSP estricta, registro de eventos sin secretos.

Modelo de amenazas: [docs/security.md](docs/security.md). Cómo informar de
una vulnerabilidad: [SECURITY.md](SECURITY.md).

## 10. Pruebas ejecutadas

Última ejecución completa (2026-11-18), con cifras reales:

| Batería | Resultado |
|---|---|
| pytest (unitarias, integración, seguridad, adversariales) | 316 superadas, cobertura 88 % |
| vitest (motor JS y paridad) | 139 superadas |
| Playwright (demo y app local contra el servidor real) | 20/20 y 4/4 |
| SAST (bandit, CodeQL), lint y tipos (ruff, mypy `--strict`, eslint) | 0 hallazgos |
| Secretos (gitleaks, historial completo) | 0 |
| SCA (DepGuard, OSV-Scanner, npm audit) sobre las dependencias propias | 0 vulnerabilidades |
| SBOM SPDX/CycloneDX contra los esquemas oficiales | 0 violaciones |
| DAST (OWASP ZAP autenticado contra `depguard serve`) | 0 alertas High/Medium/Low |
| Validación cruzada con OSV-Scanner en lockfiles reales | 19/19 y 7/7 avisos coincidentes |

Informe completo: [docs/audit/03-informe-pruebas.md](docs/audit/03-informe-pruebas.md).

## 11. Limitaciones conocidas

- Solo vulnerabilidades **publicadas** y solo para **versiones exactas**.
- Sin análisis de alcanzabilidad: puede listar vulnerabilidades que tu código no ejecuta.
- `pom.xml` y proyectos .NET sin lockfile: solo dependencias directas.
- No analiza imágenes de contenedor ni paquetes del sistema operativo.

Lista completa: [docs/limitations.md](docs/limitations.md).

## 12. Pipeline DevSecOps

Cada push y PR ejecuta lint, tipos, SAST, tests en Python 3.11–3.14, e2e,
autoescaneo, secretos, SCA independiente, validación de SBOM y DAST; las
herramientas se verifican por SHA-256 y las dependencias de CI se instalan con
hashes. Las releases se publican sin tokens (Trusted Publishing), con
procedencia SLSA firmada, SBOM y sumas de verificación. Política de fallo y
excepciones: [docs/devsecops.md](docs/devsecops.md).

```yaml
- uses: AlejandroDukesini/Devs-Guard@<sha>
  with:
    fail-on: P1
- uses: github/codeql-action/upload-sarif@<sha>
  if: always()
  with:
    sarif_file: depguard.sarif
```

Otras plataformas: [docs/ci-cd.md](docs/ci-cd.md).

## 13. Estándares evaluados y estado real de validación

| Estándar | Resultado de la evaluación interna |
|---|---|
| OWASP ASVS 5.0 (L2, app local) | 107 de 114 requisitos L1+L2 aplicables cumplidos; 6 parciales y 1 no cumplido, con acción o desviación documentada |
| NIST SSDF (SP 800-218) | 14 de 19 prácticas cumplidas |
| OWASP SAMM 2 | Madurez media 1,7 / 3 |
| ISO/IEC 27001:2022 | Controles del Anexo A que el proyecto apoya (no certificable como producto) |

**DepGuard no está certificado.** Son evaluaciones internas con evidencia en
el repositorio; falta una prueba de penetración y una revisión independientes.
Ver [docs/compliance/informe-conformidad.md](docs/compliance/informe-conformidad.md).

## 14. ¿Cuándo usar DepGuard y cuándo otra herramienta?

| | DepGuard | OSV-Scanner | Grype | Trivy | Dependabot |
|---|---|---|---|---|---|
| Fuente | OSV (+NVD, KEV, EPSS) | OSV | Grype DB | Trivy DB | GitHub Advisory DB |
| Lockfiles / transitivas | 7 ecosistemas (+ SBOM) | muchos | vía Syft | muchos | muchos |
| Estado de parche y última versión | ✅ | parcial | ❌ | ❌ | ✅ (PRs) |
| EPSS + KEV en la priorización | ✅ con motivos | ❌ | ✅ puntuación | ❌ | EPSS visible |
| "No se pudo comprobar" ≠ "sin vulnerabilidades" | ✅ exit 3 | — | — | — | — |
| Interfaz web local | ✅ | ❌ | ❌ | ❌ | web de GitHub |
| Contenedores / SO | ❌ | ✅ | ✅ | ✅ | ❌ |

<sub>Basado en la documentación pública de cada herramienta (noviembre de 2026). Si algo está desactualizado, abre un issue.</sub>

## 15. Documentación

| | |
|---|---|
| [Arquitectura](docs/architecture.md) | Flujo interno y decisiones de diseño |
| [Ecosistemas](docs/ecosystems.md) | Archivos soportados y cómo cubrir el resto |
| [Modelo de riesgo](docs/risk-model.md) | Tabla P0–P3 y códigos de motivo |
| [Configuración](docs/configuration.md) | Políticas, excepciones, paquetes privados, app local |
| [Formatos de salida](docs/output-formats.md) | JSON, SARIF, CycloneDX/VEX, SPDX, estados de parche |
| [CI/CD](docs/ci-cd.md) · [DevSecOps](docs/devsecops.md) | Integración y pipeline de seguridad |
| [Seguridad](docs/security.md) · [Excepciones](docs/security/excepciones.md) | Modelo de amenazas y riesgos residuales |
| [Auditoría](docs/audit/) | Auditoría inicial, registro de vulnerabilidades, informe de pruebas, informe final |
| [Cumplimiento](docs/compliance/) | ASVS 5.0, NIST SSDF, SAMM, ISO 27001, informe de conformidad |
| [**Limitaciones**](docs/limitations.md) | Qué no detecta y cuándo se equivoca |
| [Releases](docs/releasing.md) · [Changelog](CHANGELOG.md) | Versionado, firma y verificación |

## 16. Contribuciones y contacto

Las contribuciones son bienvenidas: [CONTRIBUTING.md](CONTRIBUTING.md). Las
vulnerabilidades del propio DepGuard se informan en privado (nunca en un
issue público): [SECURITY.md](SECURITY.md). Los tests usan solo datos
ficticios (`acme-*`, `CVE-2099-*`).

## 17. Licencia

[MIT](LICENSE)
