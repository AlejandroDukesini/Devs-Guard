# Seguridad del propio escáner

Un escáner procesa archivos que pueden venir de cualquier repositorio y datos
de servicios remotos. Este es su modelo de amenazas y cómo se mitiga cada punto.

## Entradas no confiables

| Amenaza | Mitigación | Dónde | Test |
|---|---|---|---|
| Ejecución de código desde manifests (scripts npm, `setup.py`, plugins) | DepGuard **solo parsea texto**; nunca ejecuta gestores de paquetes ni scripts. No hay `subprocess`, `eval`, `exec` ni `pickle` en el paquete | todo `dep_guard/` | `test_no_code_execution_primitives_in_package` |
| Lectura fuera de la raíz (symlinks, path traversal) | No se siguen enlaces simbólicos (ni directorios ni archivos); los adaptadores solo pueden leer `pyproject.toml` hermano | `discovery.py` | `test_symlinks_are_not_followed` |
| Archivos enormes / agotamiento de memoria | Límite de 25 MB por archivo, 1000 manifests, profundidad 12 | `discovery.py` | `test_oversized_file_is_refused` |
| Parsers vulnerables | `json` y `tomllib` de la biblioteca estándar; `packaging` para PEP 508; sin deserialización de objetos | adapters | — |
| Inyección en terminal (ANSI, `\r`, bidi, ancho cero) | Todo texto externo se sanea al entrar (`textutil.clean`) y se imprime como `rich.Text`, nunca como markup | `textutil.py`, `reporters/table.py` | `test_untrusted_markup_is_printed_literally` |
| Credenciales en manifests (`--index-url https://user:token@…`) | Las opciones de pip nunca se repiten en mensajes ni logs | `pypi_requirements.py` | `test_credentials_in_options_are_never_echoed` |
| Fuga de rutas locales en informes compartidos | JSON/SARIF/CycloneDX solo contienen rutas relativas a la raíz | reporters | `test_e2e` (goldens sin rutas absolutas) |

## Red

| Amenaza | Mitigación |
|---|---|
| SSRF / exfiltración | URLs constantes, solo HTTPS, *allowlist* de hosts (`api.osv.dev`, `api.first.org`, `www.cisa.gov`), sin seguir redirecciones |
| Respuestas maliciosas o corruptas | Límite de tamaño en streaming, validación de forma, IDs de aviso validados con regex antes de construir URLs |
| Privacidad | Solo se envían ecosistema, nombre y versión. `private_packages` evita enviar paquetes internos. `--offline` no hace ninguna petición |
| Caché envenenada | Clave verificada dentro de cada entrada; entrada corrupta = fallo de caché; escritura atómica; directorio con permisos 0700 |

## Fallos

La regla central: **"no se pudo comprobar" nunca se convierte en "sin
vulnerabilidades"**. Errores de red, 429, 5xx, JSON inválido o manifests
corruptos producen estado `error`/`unresolved`, veredicto `INCOMPLETE` y exit
code 3. Cualquier excepción no prevista termina con exit code 2, nunca con 0.

## Cadena de suministro del propio proyecto

- GitHub Actions fijadas por SHA, permisos mínimos (`contents: read` por defecto), `persist-credentials: false`.
- CodeQL (Python, JavaScript, Actions), bandit, ruff (reglas `S`), mypy estricto.
- DepGuard se escanea a sí mismo en CI y sube SARIF a code scanning.
- Dependabot para pip, npm y Actions; dependency-review en PRs; OpenSSF Scorecard.
- Releases: PyPI Trusted Publishing (sin tokens), attestations de procedencia
  SLSA firmadas con Sigstore, SBOM CycloneDX y `SHA256SUMS` en cada release.

## Riesgos residuales conocidos

- La integridad de los datos depende de OSV.dev, FIRST y CISA (vía HTTPS).
- La caché local la puede modificar cualquier proceso con permisos del usuario.
- El análisis no evalúa marcadores de entorno ni alcanzabilidad (ver limitations.md).
