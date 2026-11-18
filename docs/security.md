# Seguridad del propio DepGuard

Un escáner procesa archivos que pueden venir de cualquier repositorio y datos
de servicios remotos; la aplicación local además escucha en un puerto del
equipo. Este documento es su modelo de amenazas y cómo se mitiga cada punto.
La evaluación frente a estándares está en [compliance/](compliance/).

## 1. Entradas no confiables (motor, CLI y aplicación local)

| Amenaza | Mitigación | Dónde | Test |
|---|---|---|---|
| Ejecución de código desde manifests (scripts npm, `setup.py`, `conftest.py`, plugins de Gradle/Maven) | DepGuard **solo parsea texto**; nunca ejecuta gestores de paquetes ni scripts. No hay `subprocess`, `eval`, `exec` ni `pickle` en el paquete | todo `dep_guard/` | `test_no_code_execution_primitives_in_package`, `test_scanned_projects_are_never_executed` |
| Lectura fuera de la raíz (symlinks, path traversal) | No se siguen enlaces simbólicos; los adaptadores solo leen hermanos de una lista cerrada (`pyproject.toml`, `package.json`, `Cargo.toml`, `composer.json`, `Pipfile`) | `discovery.py` | `test_symlinks_are_not_followed` |
| Archivos enormes / agotamiento de memoria | 25 MB por archivo, 1000 manifests, profundidad 12 | `discovery.py` | `test_oversized_file_is_refused` |
| Anidamiento hostil (JSON/TOML/YAML) | `RecursionError` invalida solo ese archivo | `engine.py`, `config.py` | `test_hostile_nesting_*` |
| YAML "billion laughs" | Se rechaza cualquier alias antes de construir objetos; `SafeLoader` | `adapters/safe_formats.py` | `test_yaml_alias_bomb_is_refused_before_expansion` |
| XXE y expansión de entidades XML | Se rechaza todo XML con `DOCTYPE`/`ENTITY`; ElementTree no resuelve entidades externas | `adapters/safe_formats.py` | `test_xml_with_dtd_is_refused` |
| Prototype pollution (motor JS) | Mapas con `Map`; claves `__proto__`/`constructor` inertes | `web/src/core` | `untrusted keys never pollute prototypes` |
| Inyección en terminal y logs (ANSI, `\r`, bidi, ancho cero) | Todo texto externo se sanea al entrar (`textutil.clean`) | `textutil.py` | `test_untrusted_markup_is_printed_literally`, `test_security_events_are_logged_without_secrets` |
| Credenciales en manifests (`--index-url https://user:token@…`) | Las opciones de pip nunca se repiten en mensajes ni logs | `pypi_requirements.py` | `test_credentials_in_options_are_never_echoed` |
| Fuga de rutas locales en informes | JSON/SARIF/CycloneDX/SPDX solo contienen rutas relativas a la raíz | reporters | `test_scan_history_and_exports` |

## 2. Red (fuentes externas)

| Amenaza | Mitigación |
|---|---|
| SSRF / exfiltración | URLs constantes; solo HTTPS; *allowlist* de hosts (`ALLOWED_HOSTS` en `sources/http.py`); sin redirecciones; nombres de paquete codificados en la URL; IDs de aviso y CVE validados con expresiones regulares |
| Respuestas maliciosas o corruptas | Límite de tamaño en streaming (32 MB), validación de forma, versiones de registros validadas |
| Certificados | `httpx` verifica la cadena TLS con el almacén de `certifi` (nunca `verify=False`) |
| Privacidad | A OSV, registros y NVD solo se envían ecosistema, nombre y versión. `private_packages` evita enviar paquetes internos; `--offline` no hace ninguna petición |
| Caché envenenada | Clave verificada dentro de cada entrada; entrada corrupta = fallo de caché; escritura atómica |

Hosts contactados y cuándo:

| Host | Para qué | Cuándo |
|---|---|---|
| `api.osv.dev` | estado de vulnerabilidad (fuente de verdad) | siempre (salvo `--offline`) |
| `api.first.org` | EPSS | si hay CVE y EPSS activo |
| `www.cisa.gov` | catálogo KEV | si hay hallazgos y KEV activo |
| `services.nvd.nist.gov` | CVSS v3/v4 y CWE de avisos sin vector | solo con `--nvd` |
| `pypi.org`, `registry.npmjs.org`, `index.crates.io`, `proxy.golang.org`, `repo.packagist.org`, `repo1.maven.org`, `api.nuget.org` | última versión estable | solo con `--latest` (activo por defecto en la app local) |

Límites: 16 conexiones simultáneas, *timeout* 20 s por petición
(`[sources] timeout`), 3 reintentos con *backoff* exponencial y *jitter* solo
ante 429/5xx/red, respetando `Retry-After` (máx. 30 s); NVD a 5 peticiones /
30 s sin clave (máx. 25 CVE por análisis).

## 3. Aplicación local (`depguard serve`)

Modelo de amenazas: el servidor corre con los permisos del usuario y
cualquier página web que el usuario visite puede intentar alcanzarlo, porque
escucha en un puerto local. Toda petición es hostil hasta demostrar que viene
de la página abierta por el usuario.

| Amenaza | Control | Test |
|---|---|---|
| Acceso desde la red | El socket se enlaza solo a `127.0.0.1` (sin opción para cambiarlo) | `test_serve_binds_to_loopback_only` |
| Otra página usa la API (CSRF) | Token de sesión aleatorio de 256 bits en la cabecera `Authorization` (nunca en cookie), comparado en tiempo constante | `test_api_requires_the_session_token` |
| DNS rebinding | `Host` debe ser exactamente `127.0.0.1:<puerto>` o `localhost:<puerto>` | `test_dns_rebinding_wrong_host_is_refused` |
| Peticiones de otro origen | `Origin` presente debe ser el propio; `Sec-Fetch-Site` debe ser `same-origin`/`none`; sin cabeceras CORS | `test_foreign_origins_*`, `test_cross_site_*`, `test_no_cors_preflight_is_ever_approved` |
| Path traversal / lectura arbitraria | Raíces permitidas (`--root`, por defecto la carpeta personal); comprobación léxica **antes** de tocar el disco (rechaza `..`, rutas relativas, UNC `\\host\share` que en Windows enviarían credenciales NTLM, NUL, > 4096 caracteres); después `resolve()` y nueva comprobación (symlinks/junctions) | `test_paths_outside_the_allowed_roots_are_refused`, `test_unc_paths_are_refused_before_touching_the_file_system`, `test_symlink_escape_is_refused` |
| Entradas manipuladas | Esquema `pydantic` estricto (`extra="forbid"`, `strict=True`, longitudes, `Literal`); cuerpo ≤ 16 KB; IDs de historial `^[0-9a-f]{16}$` | `test_request_bodies_are_strictly_validated`, `test_oversized_bodies_are_refused`, `test_history_ids_cannot_address_other_files` |
| Denegación de servicio | Un análisis a la vez (409); *timeout* de 600 s; `limit_concurrency=32`; *keep-alive* 5 s | `test_one_scan_at_a_time`, `test_slow_scans_time_out_and_keep_the_lock_until_they_end` |
| Robo o reutilización del token | Caduca tras 60 min de inactividad y 12 h en total; «Cerrar sesión» lo revoca en el servidor y lo borra de `sessionStorage`; llega una sola vez en el fragmento `#token=` (que el navegador no envía) y se retira de la barra de direcciones | `test_session_*`, `test_ending_the_session_revokes_the_token`, e2e `ending the session…` |
| Fuga de información | Errores genéricos (500 sin detalle); sin `/docs` ni OpenAPI; sin cabecera `Server`; `Cache-Control: no-store` en la API; métodos no usados → 405 | `test_internal_errors_do_not_leak_details`, `test_api_documentation_endpoints_are_disabled`, `test_unused_http_methods_are_refused` |
| Contenido activo | CSP `default-src 'self'`, `object-src 'none'`, `base-uri 'none'`, `frame-ancestors 'none'`; `nosniff`, `no-referrer`, COOP y CORP `same-origin`; React escapa todo el texto; enlaces solo `https://` con `rel="noopener noreferrer nofollow"` | `test_security_headers_and_no_store`, DAST (ZAP) |
| Ejecución del proyecto analizado | Solo lectura; nada se instala ni se ejecuta | `test_scanned_projects_are_never_executed` |

**Funcionalidad sensible.** Leer archivos locales (dentro de las raíces) y
abrir el navegador con `webbrowser.open` (solo la URL propia, nunca datos
externos). **Componentes de riesgo**: los parsers de formatos no confiables
(PyYAML con cargador C, ElementTree, `json`, `tomllib`) y el servidor HTTP
(uvicorn/h11); se ejecutan en el mismo proceso, sin sandbox.

**Reglas de entrada de la API**: `path` absoluta (≤ 4096 caracteres) dentro
de una raíz; opciones booleanas estrictas `latest`, `nvd`, `epss`, `kev`,
`offline`; `fail_on` ∈ {`P0`,`P1`,`P2`,`P3`,`none`} o ausente; cualquier
otro campo se rechaza (422).

**Sesión.** Un token por proceso, compartido por las pestañas del mismo
usuario. Se crea al arrancar (`secrets.token_urlsafe(32)`), no se persiste en
disco salvo con `--token-file` (automatización; archivo `0600`) y muere con
el proceso, por inactividad, por caducidad absoluta o al cerrar sesión.

## 4. Datos tratados

| Dato | Clasificación | Protección |
|---|---|---|
| Token de sesión | Secreto | Solo en memoria, `sessionStorage` de la pestaña y, si se pide, `--token-file` (0600); nunca en logs ni respuestas |
| `NVD_API_KEY` (opcional) | Secreto del usuario | Variable de entorno; solo se envía a NVD en la cabecera `apiKey`; nunca se registra |
| Rutas locales y nombres de proyectos | Interno | Solo en la app local y su historial; los informes exportables usan rutas relativas |
| Inventario de dependencias | Interno | Se envía nombre+versión a las fuentes documentadas; `private_packages` lo evita |
| Historial de análisis | Interno | `<caché>/history`, 50 entradas máx., borrables desde la UI |

## 5. Criptografía (inventario)

| Uso | Primitiva | Implementación |
|---|---|---|
| Token de sesión | 256 bits de CSPRNG | `secrets.token_urlsafe(32)` |
| Comparación del token | Tiempo constante | `hmac.compare_digest` |
| IDs de historial | 64 bits de CSPRNG (no son secretos; la API exige el token) | `secrets.token_hex(8)` |
| Claves de caché, sellos de informes, `SHA256SUMS` | SHA-256 (integridad, no secreto) | `hashlib`, Web Crypto |
| Transporte saliente | TLS (versión y cifrados de OpenSSL de la plataforma) | `httpx` + `certifi` |
| Releases | Firmas Sigstore (procedencia SLSA) | GitHub Actions |

No hay claves de larga duración gestionadas por DepGuard.

## 6. Registro de eventos de seguridad

`depguard serve` escribe en `stderr` (logger `depguard.server.security`):
`<UTC ISO-8601>Z WARNING … denied status=<código> reason=<motivo>
method=<método> path=<ruta> client=<IP>` para cada petición rechazada
(token, Host, Origin, Sec-Fetch, tamaño, ruta fuera de raíces, sesión
caducada o cerrada) y `ERROR` para errores inesperados. Nunca contiene el
token; los campos se sanean contra inyección. No hay retención ni envío a un
sistema externo: es una herramienta local monousuario (ver riesgos residuales).

## 7. Fallos

La regla central: **"no se pudo comprobar" nunca se convierte en "sin
vulnerabilidades"**. Errores de red, 429, 5xx, JSON inválido, manifests
corruptos, archivos reconocidos sin adaptador o un directorio sin manifests
producen veredicto `INCOMPLETE` (exit 3). Cualquier excepción no prevista
termina con exit 2 (CLI) o 500 genérico (app local), nunca con PASS.

## 8. Cadena de suministro del propio proyecto

Ver [devsecops.md](devsecops.md): acciones fijadas por SHA, herramientas con
SHA-256, lock de Python con hashes, `npm ci --ignore-scripts`, CodeQL, bandit,
gitleaks, OSV-Scanner, npm audit, DAST con ZAP, Scorecard, Trusted Publishing,
procedencia SLSA firmada, SBOM CycloneDX y SPDX.

## 9. Riesgos residuales

Registrados con fecha de revisión en
[security/excepciones.md](security/excepciones.md): caché local modificable por
el mismo usuario; protección del `--token-file` en Windows mediante ACL;
hilo de análisis no interrumpible; TOCTOU entre la validación de una ruta y
su lectura si otro proceso local la sustituye por un enlace; logs sin
protección contra modificación; el token queda en el historial del navegador
(fragmento) hasta su caducidad.
