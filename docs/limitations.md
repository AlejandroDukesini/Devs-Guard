# Limitaciones

Una herramienta de seguridad que promete detectarlo todo miente. Esto es lo que
DepGuard **no** hace, y cuándo puede equivocarse.

## Qué detecta

Vulnerabilidades **conocidas y publicadas** en [OSV.dev](https://osv.dev) para
la **versión exacta** de cada paquete que aparece en un lockfile, un
`requirements.txt` con versiones fijadas, un `package.json` con versiones
exactas o un SBOM CycloneDX.

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
| `package.json` sin `package-lock.json` | Solo se ven dependencias directas | Versiona el lockfile |
| `package-lock.json` v1 (npm ≤ 6) | No soportado: error explícito | Regenera con npm ≥ 7 |
| `-r otro.txt` dentro de requirements | No se siguen includes | Escanea el directorio (encuentra todos los `requirements*.txt`) |
| Dependencias git/URL/locales | No tienen versión de registro | Estado `unresolved` con motivo |
| Paquetes en `private_packages` | No se envían a OSV por diseño | Escaneo interno con otra fuente |
| OSV/red caídos | No se puede determinar | Exit 3 (`INCOMPLETE`), nunca PASS |
| `yarn.lock`, `pnpm-lock.yaml`, `Pipfile.lock`, Maven/Gradle nativos | Sin adaptador todavía | Genera CycloneDX (cdxgen, Syft, plugins CycloneDX) |
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

## Ecosistemas

Ver [ecosystems.md](ecosystems.md).
