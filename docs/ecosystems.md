# Ecosistemas y archivos soportados

`depguard formats` muestra esta lista desde la propia herramienta. Cada
formato tiene su propio adaptador (`dep_guard/adapters/`) y un fixture con su
inventario exacto en `tests/test_ecosystems.py`.

| Archivo | Ecosistema (OSV) | Transitivas | Directa / transitiva | prod / dev | Notas |
|---|---|---|---|---|---|
| `package-lock.json`, `npm-shrinkwrap.json` (v2, v3) | npm | ✅ | ✅ con ruta | ✅ (`dev` de npm) | Workspaces y alias `npm:`; v1 rechazado explícitamente |
| `pnpm-lock.yaml` (v5, v6, v9) | npm | ✅ | ✅ con ruta | ✅ | Workspaces (`importers`), sufijos de peers, alias; `link:`/`file:`/git → `unresolved` |
| `yarn.lock` (Yarn 1 y Berry) | npm | ✅ | ✅ (Yarn 1 necesita `package.json` al lado) | ✅ | Protocolo `patch:` de Berry; `file:`/git → `unresolved` |
| `package.json` | npm | ❌ | solo directas | ✅ | Solo si no hay lockfile al lado; rangos → `unresolved` |
| `poetry.lock` (+ `pyproject.toml`) | PyPI | ✅ | ✅ | ✅ (`groups`/`category`) | Fuentes git/directorio → `unresolved` |
| `uv.lock` | PyPI | ✅ | ✅ | ✅ | |
| `Pipfile.lock` (+ `Pipfile`) | PyPI | ✅ | ✅ si hay `Pipfile` | ✅ (`default`/`develop`) | `editable`/`path`/git → `unresolved` |
| `requirements*.txt`, `requirements/*.txt` | PyPI | ❌ (salvo `pip freeze`) | todas directas | por nombre de archivo | Solo `==`/`===`; PEP 508, `--hash`, continuaciones; UTF-16 de PowerShell |
| `pyproject.toml` (PEP 621, PEP 735, Poetry) | PyPI | ❌ | solo directas | ✅ | Solo si no hay `poetry.lock`/`uv.lock`/`Pipfile.lock`; rangos → `unresolved` |
| `Cargo.lock` (+ `Cargo.toml`) | crates.io | ✅ | ✅ con ruta | ✅ (`[dev-dependencies]`) | Crates del workspace = raíz; git/path → `unresolved` |
| `go.mod` | Go | ✅ (lista de compilación) | ✅ (`// indirect`) | desconocido | `replace` aplicado; `replace` a ruta local → `unresolved`; `go.sum` no se usa |
| `composer.lock` (+ `composer.json`) | Packagist | ✅ | ✅ | ✅ (`packages-dev`) | Ramas `dev-*` → `unresolved` |
| `composer.json` | Packagist | ❌ | solo directas | ✅ | Solo si no hay `composer.lock`; restricciones → `unresolved` |
| `packages.lock.json` | NuGet | ✅ | ✅ con ruta | desconocido | Fusiona todos los *target frameworks*; referencias `Project` omitidas |
| `*.csproj`, `*.fsproj`, `*.vbproj`, `Directory.Packages.props` | NuGet | ❌ | solo directas | desconocido | Versión simple = mínima aplicable; `[1.2.3]` exacta; rangos y `$(Prop)` → `unresolved` |
| `pom.xml` | Maven | ❌ | solo directas | ✅ (`test` → dev) | Propiedades locales y `dependencyManagement`; versión heredada de un POM padre/BOM → `unresolved` |
| `gradle.lockfile`, `buildscript-gradle.lockfile`, `dependency-locks/*.lockfile` | Maven | ✅ | desconocido | ✅ (configuraciones `test*`) | Requiere *dependency locking*; los scripts de Gradle nunca se evalúan |
| `*.cdx.json`, `bom.json`, `sbom.json` (CycloneDX JSON) | PyPI, npm, Maven, Go, crates.io, NuGet, RubyGems, Packagist, Pub, Hex | según el SBOM | ✅ si hay grafo | `scope: excluded` → dev | `deb`/`rpm`/`apk` no soportados |

## Archivos reconocidos pero no analizados

Estos archivos se detectan y **hacen el resultado `INCOMPLETE`** (exit 3) en
lugar de ignorarse en silencio:

| Archivo | Qué hacer |
|---|---|
| `Cargo.toml` sin `Cargo.lock` (ni en carpetas superiores) | Versionar `Cargo.lock` |
| `build.gradle`, `build.gradle.kts` sin `gradle.lockfile` | Activar *dependency locking* |
| `Pipfile` sin `Pipfile.lock` | Versionar `Pipfile.lock` |
| `Gemfile.lock`, `pdm.lock`, `bun.lock(b)`, `pubspec.lock`, `mix.lock`, `Package.resolved` | Generar un SBOM CycloneDX con la herramienta del ecosistema y escanearlo |

## Formatos que dependen del gestor de paquetes

`pom.xml` y los proyectos .NET sin `packages.lock.json` solo muestran
dependencias directas: el árbol completo exige la lógica del gestor (POM
padres remotos, BOMs, resolución de NuGet), y DepGuard nunca ejecuta el gestor.
Para cobertura completa:

```bash
# Maven
mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom   # target/bom.json
depguard scan target/bom.json

# .NET: activar el lockfile
dotnet restore --use-lock-file

# Cualquier proyecto
syft dir:. -o cyclonedx-json=sbom.cdx.json
depguard scan sbom.cdx.json
```

## Versiones de corrección

Para npm (SemVer) y PyPI (PEP 440) el orden de versiones es exacto. Para el
resto se usa un comparador conservador: segmentos numéricos (`2.14.1` <
`2.15.0`); ante un calificador ambiguo (`-alpha`, `.RELEASE`) el orden se
declara desconocido y se listan las candidatas en vez de adivinar. Esto nunca
afecta a *si* una versión es vulnerable, que lo decide OSV.

## Demo web

La demo del navegador (`web/`) conserva el subconjunto original (npm
`package-lock.json`/`package.json`, Poetry, uv, requirements y CycloneDX),
con paridad verificada frente al motor Python. Los formatos nuevos están en el
motor Python, que es el que usan la CLI y la aplicación local.

## Añadir un ecosistema

Ver [CONTRIBUTING.md](../CONTRIBUTING.md#adding-an-ecosystem).
