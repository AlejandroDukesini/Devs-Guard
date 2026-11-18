# Limitaciones

Una herramienta de seguridad que promete detectarlo todo miente. Esto es lo que
DepGuard **no** hace, y cuándo puede equivocarse.

## Qué detecta

Vulnerabilidades **conocidas y publicadas** en [OSV.dev](https://osv.dev) para
la **versión exacta** de cada paquete que aparece en un lockfile o manifest
soportado ([ecosystems.md](ecosystems.md)) o en un SBOM CycloneDX. OSV agrega,
entre otras, las bases de GitHub Security Advisories (GHSA), PyPA, RustSec, Go
y los CVE asociados; DepGuard no consulta GHSA por separado porque duplicaría
los mismos avisos.

## Qué no detecta

- Vulnerabilidades no publicadas (0-day) o publicadas solo en bases privadas o
  comerciales que OSV no agrega.
- Código malicioso en paquetes (typosquatting, paquetes comprometidos) salvo
  que exista un aviso `MAL-` en OSV para esa versión.
- Vulnerabilidades en tu propio código (para eso: SAST, por ejemplo CodeQL).
- Dependencias del sistema operativo o de imágenes de contenedor (usa Trivy o
  Grype para imágenes, o genera un SBOM y revisa los tipos soportados).
- Dependencias vendorizadas o copiadas sin manifest.

## Falsos negativos (vulnerabilidades que no verás)

| Escenario | Por qué | Qué hacer |
|---|---|---|
| `flask>=2.0`, `^4.18.2`, `*` | Sin versión exacta no se consulta (estado `unresolved`) | Usa lockfiles o `pip freeze` / `pip-compile` / `uv export` |
| `package.json`, `composer.json`, `pyproject.toml`, `*.csproj` sin lockfile | Solo se ven dependencias directas | Versiona el lockfile |
| `pom.xml` | Solo directas; versiones heredadas de un POM padre/BOM → `unresolved` | SBOM con `cyclonedx-maven-plugin` |
| `package-lock.json` v1 (npm ≤ 6) | No soportado: error explícito | Regenera con npm ≥ 7 |
| `-r otro.txt` dentro de requirements | No se siguen includes | Escanea el directorio (encuentra todos los `requirements*.txt`) |
| Dependencias git/URL/locales | No tienen versión de registro | Estado `unresolved` con motivo |
| Paquetes en `private_packages` | No se envían a OSV por diseño | Escaneo interno con otra fuente |
| OSV/red caídos | No se puede determinar | Exit 3 (`INCOMPLETE`), nunca PASS |
| `Gemfile.lock`, `pdm.lock`, `bun.lock`, `pubspec.lock`, `mix.lock`, `Package.resolved` | Sin adaptador: se avisa y el resultado es `INCOMPLETE` | Genera CycloneDX (cdxgen, Syft, plugins CycloneDX) |
| Biblioteca estándar de Go (`go` / `toolchain` en `go.mod`) | La directiva indica el mínimo, no la versión con la que se compila | Escanea el binario o un SBOM del entorno de build |
| Gradle sin *dependency locking* | Los scripts no se evalúan nunca | Activa `gradle.lockfile` |
| Tipos purl `deb`, `rpm`, `apk` en SBOM | Requieren contexto de distribución | Se listan como no soportados |

## Falsos positivos (vulnerabilidades que quizá no te afectan)

- **No hay análisis de alcanzabilidad:** si tu código nunca llama a la función
  vulnerable, el hallazgo aparece igualmente. Documenta una excepción con motivo y caducidad.
- **Marcadores de entorno** (`; sys_platform == "win32"`) no se evalúan: el
  paquete se escanea aunque no se instale en tu plataforma.
- **Ámbito prod/dev en `requirements.txt`** se deduce del nombre del archivo
  (`requirements-dev.txt`, `requirements/test.txt`…).
- Avisos con rangos mal definidos en la base de datos de origen.

## Calidad de los datos externos

- La severidad sale del vector CVSS v3.x de OSV o de la calificación del aviso;
  **CVSS v4 no se puntúa** (se usa la calificación cualitativa).
- EPSS es un modelo estadístico, no una garantía. KEV solo incluye
  explotación *confirmada* por CISA.
- Si EPSS o KEV no responden, la prioridad se calcula sin ese dato y se avisa.
- `--nvd` solo completa avisos **sin** vector CVSS en OSV y con CVE; sin
  `NVD_API_KEY` se consultan como máximo 25 CVE por análisis (límite público
  de NVD: 5 peticiones / 30 s).

## Última versión y estado de parche (`--latest`)

- "Última versión" es la última **estable** que publica el registro oficial
  (sin pre-releases, versiones *yanked* ni *snapshots*). En Maven Central se
  usa el orden de publicación de `maven-metadata.xml`.
- Una versión instalada **posterior** a la última estable (pre-release o
  versión que no existe) nunca se marca como actualizada.
- Que no haya avisos conocidos no significa que una versión sea segura; que
  exista una versión nueva no significa que corrija nada: la nota lo indica
  y DepGuard comprueba en OSV si la última versión también está afectada.
- El aviso de "cambio de versión mayor" es una heurística (SemVer); no
  analiza la API real del paquete.

## Ecosistemas

Ver [ecosystems.md](ecosystems.md).
