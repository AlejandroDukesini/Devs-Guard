# Ecosistemas y archivos soportados

`depguard formats` muestra esta lista desde la propia herramienta.

| Archivo | Ecosistema | Transitivas | Directa/transitiva | prod/dev | Notas |
|---|---|---|---|---|---|
| `package-lock.json`, `npm-shrinkwrap.json` (v2, v3) | npm | ✅ | ✅ (con ruta) | ✅ (`dev` de npm) | Workspaces y alias `npm:` soportados; v1 rechazado explícitamente |
| `package.json` | npm | ❌ | solo directas | ✅ | Solo si no hay lockfile al lado; rangos → `unresolved` |
| `poetry.lock` (+ `pyproject.toml`) | PyPI | ✅ | ✅ si hay pyproject | ✅ (`groups`/`category`) | Fuentes git/directorio → `unresolved` |
| `uv.lock` | PyPI | ✅ | ✅ | ✅ (`dev-dependencies`) | |
| `requirements*.txt`, `requirements/*.txt` | PyPI | ❌ (salvo `pip freeze`) | todas directas | por nombre de archivo | Solo `==`/`===`; PEP 508, extras, marcadores, `--hash`, continuaciones; UTF-16 de PowerShell |
| `*.cdx.json`, `bom.json`, `sbom.json` (CycloneDX JSON) | PyPI, npm, Maven, Go, crates.io, NuGet, RubyGems, Packagist, Pub, Hex | según el SBOM | ✅ si hay grafo `dependencies` | `scope: excluded` → dev | `deb`/`rpm`/`apk` no soportados |

## ¿Por qué no hay adaptador nativo para Maven, Gradle, Go, Cargo…?

Resolver correctamente esos árboles requiere la lógica del propio gestor
(perfiles de Maven, resolución de conflictos de Gradle, `go.sum` frente a la
lista de módulos realmente compilados…). Reimplementarla daría resultados
peores que las herramientas oficiales. La vía recomendada es generar un SBOM
CycloneDX con la herramienta del ecosistema y escanearlo:

```bash
# Java (Maven)
mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom   # target/bom.json
depguard scan target/bom.json

# Cualquier proyecto o imagen
syft dir:. -o cyclonedx-json=sbom.cdx.json
depguard scan sbom.cdx.json
```

## Añadir un ecosistema

Ver [CONTRIBUTING.md](../CONTRIBUTING.md#adding-an-ecosystem).
