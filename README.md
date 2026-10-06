# 🛡️ DepGuard

[![CI](https://github.com/AlejandroDukesini/Devs-Guard/actions/workflows/ci.yml/badge.svg)](https://github.com/AlejandroDukesini/Devs-Guard/actions/workflows/ci.yml)
[![CodeQL](https://github.com/AlejandroDukesini/Devs-Guard/actions/workflows/codeql.yml/badge.svg)](https://github.com/AlejandroDukesini/Devs-Guard/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/AlejandroDukesini/Devs-Guard/badge)](https://scorecard.dev/viewer/?uri=github.com/AlejandroDukesini/Devs-Guard)
[![Python](https://img.shields.io/badge/python-3.11%E2%80%933.14-blue.svg)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**Escáner de vulnerabilidades en dependencias que explica qué arreglar primero y por qué.**

DepGuard lee tus lockfiles o tu SBOM, consulta [OSV.dev](https://osv.dev),
prioriza cada vulnerabilidad con CVSS + [EPSS](https://www.first.org/epss/) +
[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) y
el contexto de tu proyecto (producción o desarrollo, directa o transitiva), y
aplica una política con un resultado determinista para CI:
`PASS`, `FAIL` o `INCOMPLETE`.

> 🌐 **Demo web:** pruébalo en el navegador sin instalar nada (carpeta [`web/`](web/), despliegue en Netlify).

```text
$ depguard scan .
DepGuard 1.0.0b1
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

<sub>Salida real de un escaneo del 2026-10-05; los datos de OSV cambian a diario.</sub>

---

## ¿Por qué DepGuard y no otra herramienta?

Si ya usas **OSV-Scanner**, **Grype**, **Trivy**, **Dependabot** o **Snyk**, probablemente no
necesitas DepGuard *para detectar*: usan las mismas fuentes de datos u otras más
amplias y cubren más ecosistemas. DepGuard está pensado para un hueco concreto:

| | DepGuard | OSV-Scanner | Grype | Trivy | Dependabot |
|---|---|---|---|---|---|
| Fuente | OSV | OSV | Grype DB | Trivy DB | GitHub Advisory DB |
| Lockfiles / transitivas | npm, Poetry, uv (+ SBOM) | muchos | vía Syft | muchos | muchos |
| Entrada SBOM CycloneDX | ✅ | ✅ | ✅ | ✅ | ❌ |
| SARIF | ✅ | ✅ | ✅ | ✅ | nativo |
| EPSS + KEV en la priorización | ✅ tabla de decisión **con motivos** | ❌ | ✅ puntuación 0–10 | ❌ | EPSS visible |
| Excepciones con motivo **y caducidad obligatorios** | ✅ | caducidad opcional | ✅ | ✅ | reglas de triaje |
| "No se pudo comprobar" ≠ "sin vulnerabilidades" | ✅ exit 3 | — | — | — | — |
| Contenedores / SO | ❌ | ✅ | ✅ | ✅ | ❌ |

<sub>Comparación basada en la documentación pública de cada herramienta (octubre de 2026). Si algo está desactualizado, abre un issue.</sub>

**Úsalo si quieres:** una decisión de CI explicable (*por qué* es P0 y no P2),
excepciones auditables que caducan, un resultado honesto cuando la red falla y
una herramienta pequeña en Python que puedes leer entera y usar como librería.

**No lo uses si necesitas:** imágenes de contenedor, más ecosistemas nativos,
análisis de alcanzabilidad o PRs automáticos de actualización. Para eso existen
Trivy/Grype, OSV-Scanner, Snyk y Dependabot/Renovate.

---

## Instalación

Requiere Python 3.11 o superior.

```bash
pip install devs-guard        # cuando se publique en PyPI (el comando es `depguard`)
# hasta entonces, desde GitHub:
pip install "git+https://github.com/AlejandroDukesini/Devs-Guard@Beta"
```

## Uso

```bash
depguard scan .                          # directorio: encuentra lockfiles y manifests
depguard scan package-lock.json          # un archivo
depguard scan sbom.cdx.json              # SBOM CycloneDX (Maven, Go, Cargo… vía purl)
depguard scan . -f sarif -o depguard.sarif
depguard scan . -f json  -o report.json
depguard scan . --fail-on P0             # solo falla con P0
depguard sbom . -o bom.cdx.json          # SBOM sin consultar vulnerabilidades (offline)
depguard formats                         # archivos soportados
```

Como librería:

```python
from dep_guard import scan

report = scan("path/to/project")
print(report.policy.verdict, report.exit_code)
for f in report.active_findings:
    print(f.priority, f.id, f.component.name, f.fixed_versions)
```

### Exit codes

| Código | Significado |
|---|---|
| `0` | PASS: política cumplida y todo comprobado |
| `1` | FAIL: política incumplida |
| `2` | Error de la herramienta (argumentos, ruta, configuración, fallo interno) |
| `3` | INCOMPLETE: algo no se pudo comprobar (red, OSV, manifest corrupto) |

## Configuración

`depguard.toml` en la raíz del proyecto (validación estricta: una clave mal
escrita es un error, no se ignora):

```toml
[policy]
fail_on_priority = "P1"
fail_on_kev = true

[sources]
private_packages = ["@acme/*"]      # nunca se envían a OSV

[[ignore]]
id = "CVE-2023-32681"
reason = "No usamos proxies con credenciales; el vector no aplica"
expires = 2027-01-31                # obligatorio: no hay excepciones permanentes
owner = "equipo-pagos"
```

Referencia completa: [docs/configuration.md](docs/configuration.md).

## Cómo prioriza

| Prioridad | Regla |
|---|---|
| **P0** | En producción **y** (en CISA KEV **o** EPSS ≥ 0.10 con severidad ≥ HIGH) |
| **P1** | Severidad ≥ HIGH en producción, **o** EPSS ≥ 0.10, **o** en KEV |
| **P2** | MEDIUM o severidad desconocida en producción; HIGH+ solo en desarrollo |
| **P3** | El resto |

Cada hallazgo incluye los motivos de su prioridad. Lo desconocido nunca
tranquiliza: ámbito desconocido = producción, severidad desconocida ≥ P2.
Detalles: [docs/risk-model.md](docs/risk-model.md).

## CI/CD

```yaml
- uses: AlejandroDukesini/Devs-Guard@<sha>
  with:
    fail-on: P1
- uses: github/codeql-action/upload-sarif@<sha>
  if: always()
  with:
    sarif_file: depguard.sarif
```

GitLab, Jenkins y más: [docs/ci-cd.md](docs/ci-cd.md).

## Documentación

| | |
|---|---|
| [Arquitectura](docs/architecture.md) | Flujo interno y decisiones de diseño |
| [Ecosistemas](docs/ecosystems.md) | Archivos soportados y cómo cubrir el resto con SBOM |
| [Modelo de riesgo](docs/risk-model.md) | Tabla P0–P3 y códigos de motivo |
| [Configuración](docs/configuration.md) | Políticas, excepciones, paquetes privados |
| [Formatos de salida](docs/output-formats.md) | JSON, SARIF, CycloneDX/VEX |
| [CI/CD](docs/ci-cd.md) | GitHub Actions, GitLab, Jenkins, exit codes |
| [Seguridad](docs/security.md) | Modelo de amenazas del propio escáner |
| [**Limitaciones**](docs/limitations.md) | Qué no detecta y cuándo se equivoca |
| [Benchmarks](docs/benchmark.md) | Metodología (sin cifras inventadas) |
| [Releases](docs/releasing.md) | Versionado, firma y verificación |

## Limitaciones (resumen)

- Solo vulnerabilidades **publicadas** en OSV.dev y solo para **versiones exactas**.
- Sin análisis de alcanzabilidad: puede listar vulnerabilidades que tu código no ejecuta.
- `yarn.lock`, `pnpm-lock.yaml`, Maven y Gradle nativos aún no: usa un SBOM CycloneDX.
- No analiza imágenes de contenedor ni paquetes del sistema operativo.

Lista completa: [docs/limitations.md](docs/limitations.md).

## Desarrollo

```bash
pip install -e ".[dev]"
ruff check dep_guard tests && mypy && bandit -q -c pyproject.toml -r dep_guard && pytest --cov
```

Los tests no usan datos reales de vulnerabilidades: `fixtures/` contiene paquetes
y CVE ficticios (`acme-*`, `CVE-2099-*`). Ver [CONTRIBUTING.md](CONTRIBUTING.md)
y [SECURITY.md](SECURITY.md).

## Licencia

[MIT](LICENSE)
