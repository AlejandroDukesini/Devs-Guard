# OWASP ASVS 5.0 — matriz de requisitos

- Objeto evaluado: aplicación local `depguard serve` (API FastAPI + interfaz React).
  La CLI no es una aplicación web; sus controles están en `docs/security.md` §1-2.
- Nivel objetivo: **L2**. Los requisitos L3 también se evalúan.
- Fuente: `OWASP_Application_Security_Verification_Standard_5.0.0_en.flat.json`,
  publicación oficial `v5.0.0_release` de OWASP/ASVS (CC BY-SA 4.0). Identificadores, niveles
  y textos (abreviados) son los oficiales.
- Fecha: 2026-11-18. Evaluación **interna**: no sustituye una verificación independiente.

## Resumen

| Estado | Requisitos |
|---|---|
| Cumple (verificado internamente) | 137 |
| Parcial | 14 |
| No cumple | 3 |
| No aplica | 191 |
| No evaluado | 0 |
| **Total** | **345** |

| Nivel | Cumple | Parcial | No cumple | No aplica |
|---|---|---|---|---|
| L1 | 35 | 1 | 0 | 34 |
| L2 | 72 | 5 | 1 | 105 |
| L3 | 30 | 8 | 2 | 52 |

Requisitos L1+L2 aplicables: **114**; cumplidos: **107** (93 %). «No cumple» en L1/L2: V16.4.2. Parciales en L1/L2: V4.2.1, V6.3.3, V12.3.1, V13.3.1, V14.2.1, V16.3.1. Cada uno tiene su acción o desviación documentada abajo.

Todos los estados «Cumple» son **cumplimiento comprobado internamente** (test, configuración o
revisión citada). Ninguno ha sido validado todavía por un evaluador independiente.

## Deficiencias y acciones

| Requisito | Nivel | Estado | Deficiencia / acción |
|---|---|---|---|
| V1.3.12 | L3 | Parcial | Sin prueba automática de ReDoS: añadir fuzzing de las expresiones aplicadas a manifests |
| V1.5.3 | L3 | Parcial | No evaluado frente a claves duplicadas entre parsers distintos |
| V3.2.3 | L3 | Parcial | Sin verificación específica de DOM clobbering |
| V3.4.7 | L3 | No cumple | L3, fuera del nivel objetivo: no hay colector de informes en una herramienta local |
| V3.7.5 | L3 | No cumple | L3, fuera del nivel objetivo |
| V4.2.1 | L2 | Parcial | No probado por el proyecto: añadir pruebas de request smuggling (CL/TE) |
| V6.3.3 | L2 | Parcial | Desviación documentada: herramienta local monousuario en loopback |
| V11.1.3 | L3 | Parcial | Sin herramienta de descubrimiento criptográfico automatizada |
| V12.3.1 | L2 | Parcial | La conexión navegador↔servidor es HTTP en loopback (no sale del equipo): desviación documentada |
| V13.3.1 | L2 | Parcial | No hay gestor de secretos: `NVD_API_KEY` se lee de una variable de entorno (herramienta local) |
| V13.4.6 | L3 | Parcial | `/api/info` devuelve la versión de DepGuard al usuario autenticado (intencionado) |
| V14.2.1 | L1 | Parcial | Queda en el historial local del navegador hasta caducar (RR-06). Mejora: intercambio por código de un solo uso |
| V14.2.7 | L3 | Parcial | Sin caducidad temporal automática |
| V15.2.5 | L3 | Parcial | Sin sandbox para los parsers de formatos no confiables |
| V15.4.2 | L3 | Parcial | TOCTOU con enlaces requiere escritura local del mismo usuario (RR-04) |
| V16.3.1 | L2 | Parcial | Los aciertos no se registran por petición (cada llamada se autentica); solo se anuncia el inicio de sesión |
| V16.4.2 | L2 | No cumple | Sin protección contra modificación (RR-05) |

## Matriz completa


### V1 Encoding and Sanitization

| Requisito | Nivel | Resumen oficial | Estado | Evidencia |
|---|---|---|---|---|
| V1.1.1 | L2 | input is decoded or unescaped into a canonical form only once, it is only decoded when encoded data in… | Cumple (verificado internamente) | Starlette decodifica query y JSON una sola vez; las rutas se validan después (`server/security.py`) |
| V1.1.2 | L2 | the application performs output encoding and escaping either as a final step before being used by the… | Cumple (verificado internamente) | React escapa al renderizar; JSON lo serializa el framework; no hay plantillas |
| V1.2.1 | L1 | output encoding for an HTTP response, HTML document, or XML document is relevant for the context required,… | Cumple (verificado internamente) | Sin `dangerouslySetInnerHTML`/`innerHTML` en `web/src` (búsqueda); cabeceras fijadas por el framework |
| V1.2.2 | L1 | when dynamically building URLs, untrusted data is encoded according to its context (e.g., URL encoding or… | Cumple (verificado internamente) | `encodeURIComponent` en `web/src/local/api.js`; `quote()` en `sources/registries.py`; solo enlaces `https://` (`FindingRow.safeHref`) |
| V1.2.3 | L1 | output encoding or escaping is used when dynamically building JavaScript content (including JSON), to… | Cumple (verificado internamente) | JSON generado por `json.dumps` / `JSON.stringify` |
| V1.2.4 | L1 | data selection or database queries (e.g., SQL, HQL, NoSQL, Cypher) use parameterized queries, ORMs, entity… | No aplica | No hay base de datos |
| V1.2.5 | L1 | the application protects against OS command injection and that operating system calls use parameterized OS… | Cumple (verificado internamente) | Sin `subprocess`/`os.system` (`test_no_code_execution_primitives_in_package`); `webbrowser.open` solo con la URL propia |
| V1.2.6 | L2 | the application protects against LDAP injection vulnerabilities, or that specific security controls to… | No aplica | No hay LDAP |
| V1.2.7 | L2 | the application is protected against XPath injection attacks by using query parameterization or… | No aplica | No se evalúan expresiones XPath con datos de entrada |
| V1.2.8 | L2 | LaTeX processors are configured securely (such as not using the "--shell-escape" flag) and an allowlist of… | No aplica | No hay LaTeX |
| V1.2.9 | L2 | the application escapes special characters in regular expressions (typically using a backslash) to prevent… | Cumple (verificado internamente) | No se construyen expresiones regulares con datos no confiables (patrones propios de `depguard.toml` vía `fnmatch`) |
| V1.2.10 | L3 | the application is protected against CSV and Formula Injection. The application must follow the escaping… | No aplica | No exporta CSV ni hojas de cálculo |
| V1.3.1 | L1 | all untrusted HTML input from WYSIWYG editors or similar is sanitized using a well-known and secure HTML… | No aplica | No acepta HTML de usuario |
| V1.3.2 | L1 | the application avoids the use of eval() or other dynamic code execution features such as Spring… | Cumple (verificado internamente) | Sin `eval`/`exec`/`new Function` (test + búsqueda en `web/src`) |
| V1.3.3 | L2 | data being passed to a potentially dangerous context is sanitized beforehand to enforce safety measures,… | Cumple (verificado internamente) | `textutil.clean` sobre todo texto externo, con longitud máxima |
| V1.3.4 | L2 | user-supplied Scalable Vector Graphics (SVG) scriptable content is validated or sanitized to contain only… | No aplica | No acepta SVG de usuario |
| V1.3.5 | L2 | the application sanitizes or disables user-supplied scriptable or expression template language content,… | No aplica | No acepta Markdown, CSS ni plantillas de usuario |
| V1.3.6 | L2 | the application protects against Server-side Request Forgery (SSRF) attacks, by validating untrusted data… | Cumple (verificado internamente) | Allowlist de hosts, solo HTTPS, sin redirecciones (`sources/http.py`; `test_registry_hosts_are_allowlisted_and_redirects_refused`) |
| V1.3.7 | L2 | the application protects against template injection attacks by not allowing templates to be built based on… | No aplica | No hay plantillas del lado servidor |
| V1.3.8 | L2 | the application appropriately sanitizes untrusted input before use in Java Naming and Directory Interface… | No aplica | No hay JNDI |
| V1.3.9 | L2 | the application sanitizes content before it is sent to memcache to prevent injection attacks. | No aplica | No hay memcache |
| V1.3.10 | L2 | format strings which might resolve in an unexpected or malicious way when used are sanitized before being… | Cumple (verificado internamente) | Logging parametrizado (`%s`); valores saneados |
| V1.3.11 | L2 | the application sanitizes user input before passing to mail systems to protect against SMTP or IMAP injection. | No aplica | No envía correo |
| V1.3.12 | L3 | regular expressions are free from elements causing exponential backtracking, and ensure untrusted input is… | Parcial | Expresiones revisadas manualmente sin cuantificadores anidados — Sin prueba automática de ReDoS: añadir fuzzing de las expresiones aplicadas a manifests |
| V1.4.1 | L2 | the application uses memory-safe string, safer memory copy and pointer arithmetic to detect or prevent… | No aplica | Python y JavaScript gestionan la memoria; no hay código nativo propio |
| V1.4.2 | L2 | sign, range, and input validation techniques are used to prevent integer overflows. | No aplica | Enteros de precisión arbitraria (Python); sin aritmética de punteros |
| V1.4.3 | L2 | dynamically allocated memory and resources are released, and that references or pointers to freed memory… | No aplica | Memoria gestionada por el intérprete |
| V1.5.1 | L1 | the application configures XML parsers to use a restrictive configuration and that unsafe features such as… | Cumple (verificado internamente) | XML con DOCTYPE/ENTITY rechazado (`adapters/safe_formats.py`; `test_xml_with_dtd_is_refused`) |
| V1.5.2 | L2 | deserialization of untrusted data enforces safe input handling, such as using an allowlist of object types… | Cumple (verificado internamente) | `json`, `tomllib`, YAML `SafeLoader` sin alias; sin `pickle` (`test_yaml_alias_bomb_is_refused_before_expansion`) |
| V1.5.3 | L3 | different parsers used in the application for the same data type (e.g., JSON parsers, XML parsers, URL… | Parcial | Informe JSON generado igual en Python y JS (goldens compartidos) — No evaluado frente a claves duplicadas entre parsers distintos |

### V2 Validation and Business Logic

| Requisito | Nivel | Resumen oficial | Estado | Evidencia |
|---|---|---|---|---|
| V2.1.1 | L1 | the application's documentation defines input validation rules for how to check the validity of data items… | Cumple (verificado internamente) | Reglas de entrada de la API documentadas (`docs/security.md` §3) |
| V2.1.2 | L2 | the application's documentation defines how to validate the logical and contextual consistency of combined… | No aplica | No hay campos combinados con reglas de coherencia |
| V2.1.3 | L2 | expectations for business logic limits and validations are documented, including both per-user and… | Cumple (verificado internamente) | Límites documentados (`docs/security.md`): 1 análisis a la vez, 16 KB, 600 s, 25 MB/archivo, 1000 manifests |
| V2.2.1 | L1 | input is validated to enforce business or functional expectations for that input. This should either use… | Cumple (verificado internamente) | `pydantic` estricto (`extra=forbid`, `strict=True`, `Literal`, longitudes) y validación de rutas (`test_request_bodies_are_strictly_validated`) |
| V2.2.2 | L1 | the application is designed to enforce input validation at a trusted service layer. While client-side… | Cumple (verificado internamente) | Toda validación en el backend; la UI no es un control |
| V2.2.3 | L2 | the application ensures that combinations of related data items are reasonable according to the… | No aplica | No hay datos combinados |
| V2.3.1 | L1 | the application will only process business logic flows for the same user in the expected sequential step… | No aplica | No hay flujos de varios pasos |
| V2.3.2 | L2 | business logic limits are implemented per the application's documentation to avoid business logic flaws… | Cumple (verificado internamente) | Límites implementados (`test_one_scan_at_a_time`, `test_oversized_bodies_are_refused`) |
| V2.3.3 | L2 | transactions are being used at the business logic level such that either a business logic operation… | Cumple (verificado internamente) | Historial con escritura atómica (`tempfile` + `os.replace`) |
| V2.3.4 | L2 | business logic level locking mechanisms are used to ensure that limited quantity resources (such as… | Cumple (verificado internamente) | Un análisis a la vez, liberado por el propio hilo (`test_slow_scans_time_out_and_keep_the_lock_until_they_end`) |
| V2.3.5 | L3 | high-value business logic flows require multi-user approval to prevent unauthorized or accidental actions.… | No aplica | No hay operaciones de alto valor que requieran varios aprobadores |
| V2.4.1 | L2 | anti-automation controls are in place to protect against excessive calls to application functions that… | Cumple (verificado internamente) | Concurrencia 1 análisis, `limit_concurrency=32`, cuerpo 16 KB, timeouts |
| V2.4.2 | L3 | business logic flows require realistic human timing, preventing excessively rapid transaction submissions. | No aplica | No hay transacciones humanas cronometrables |

### V3 Web Frontend Security

| Requisito | Nivel | Resumen oficial | Estado | Evidencia |
|---|---|---|---|---|
| V3.1.1 | L3 | application documentation states the expected security features that browsers using the application must… | Cumple (verificado internamente) | Mecanismos del navegador documentados (`docs/security.md` §3) |
| V3.2.1 | L1 | security controls are in place to prevent browsers from rendering content or functionality in HTTP… | Cumple (verificado internamente) | `Sec-Fetch-Site` validado; exportaciones con `Content-Disposition: attachment`; `nosniff` |
| V3.2.2 | L1 | content intended to be displayed as text, rather than rendered as HTML, is handled using safe rendering… | Cumple (verificado internamente) | React renderiza texto; sin `innerHTML` |
| V3.2.3 | L3 | the application avoids DOM clobbering when using client-side JavaScript by employing explicit variable… | Parcial | Módulos ES, sin variables globales en `document` — Sin verificación específica de DOM clobbering |
| V3.3.1 | L1 | cookies have the 'Secure' attribute set, and if the '\__Host-' prefix is not used for the cookie name, the… | No aplica | No se usan cookies (el token viaja en la cabecera Authorization). |
| V3.3.2 | L2 | each cookie's 'SameSite' attribute value is set according to the purpose of the cookie, to limit exposure… | No aplica | No se usan cookies (el token viaja en la cabecera Authorization). |
| V3.3.3 | L2 | cookies have the '__Host-' prefix for the cookie name unless they are explicitly designed to be shared… | No aplica | No se usan cookies (el token viaja en la cabecera Authorization). |
| V3.3.4 | L2 | if the value of a cookie is not meant to be accessible to client-side scripts (such as a session token),… | No aplica | No se usan cookies (el token viaja en la cabecera Authorization). |
| V3.3.5 | L3 | when the application writes a cookie, the cookie name and value length combined are not over 4096 bytes.… | No aplica | No se usan cookies (el token viaja en la cabecera Authorization). |
| V3.4.1 | L1 | a Strict-Transport-Security header field is included on all responses to enforce an HTTP Strict Transport… | No aplica | HTTP solo en `127.0.0.1` (no sale del equipo); HSTS no es aplicable a loopback sin TLS |
| V3.4.2 | L1 | the Cross-Origin Resource Sharing (CORS) Access-Control-Allow-Origin header field is a fixed value by the… | Cumple (verificado internamente) | No se emite ninguna cabecera CORS (`test_no_cors_preflight_is_ever_approved`) |
| V3.4.3 | L2 | HTTP responses include a Content-Security-Policy response header field which defines directives to ensure… | Cumple (verificado internamente) | CSP global `default-src 'self'`, `object-src 'none'`, `base-uri 'none'` (L2); nonces por respuesta (L3) no implementados |
| V3.4.4 | L2 | all HTTP responses contain an 'X-Content-Type-Options: nosniff' header field. This instructs browsers not… | Cumple (verificado internamente) | `nosniff` en todas las respuestas (`test_security_headers_and_no_store`) |
| V3.4.5 | L2 | the application sets a referrer policy to prevent leakage of technically sensitive data to third-party… | Cumple (verificado internamente) | `Referrer-Policy: no-referrer` y `<meta name=referrer>` |
| V3.4.6 | L2 | the web application uses the frame-ancestors directive of the Content-Security-Policy header field for… | Cumple (verificado internamente) | `frame-ancestors 'none'` en todas las respuestas |
| V3.4.7 | L3 | the Content-Security-Policy header field specifies a location to report violations. | No cumple | Sin `report-to`/`report-uri` — L3, fuera del nivel objetivo: no hay colector de informes en una herramienta local |
| V3.4.8 | L3 | all HTTP responses that initiate a document rendering (such as responses with Content-Type text/html),… | Cumple (verificado internamente) | `Cross-Origin-Opener-Policy: same-origin` |
| V3.5.1 | L1 | Verify that, if the application does not rely on the CORS preflight mechanism to prevent disallowed… | Cumple (verificado internamente) | Token en `Authorization` (no CORS-safelisted) + validación de `Origin` |
| V3.5.2 | L1 | Verify that, if the application relies on the CORS preflight mechanism to prevent disallowed cross-origin… | Cumple (verificado internamente) | Sin la cabecera `Authorization` toda la API responde 401 |
| V3.5.3 | L1 | HTTP requests to sensitive functionality use appropriate HTTP methods such as POST, PUT, PATCH, or DELETE,… | Cumple (verificado internamente) | Acciones con POST/DELETE; lecturas GET protegidas por token y `Sec-Fetch-Site` |
| V3.5.4 | L2 | separate applications are hosted on different hostnames to leverage the restrictions provided by… | No aplica | Una sola aplicación por origen (puerto propio) |
| V3.5.5 | L2 | messages received by the postMessage interface are discarded if the origin of the message is not trusted,… | No aplica | No usa `postMessage` |
| V3.5.6 | L3 | JSONP functionality is not enabled anywhere across the application to avoid Cross-Site Script Inclusion… | Cumple (verificado internamente) | Sin JSONP |
| V3.5.7 | L3 | data requiring authorization is not included in script resource responses, like JavaScript files, to… | Cumple (verificado internamente) | Los scripts son estáticos y no contienen datos |
| V3.5.8 | L3 | authenticated resources (such as images, videos, scripts, and other documents) can be loaded or embedded… | Cumple (verificado internamente) | `Cross-Origin-Resource-Policy: same-origin` + `Sec-Fetch-Site` |
| V3.6.1 | L3 | client-side assets, such as JavaScript libraries, CSS, or web fonts, are only hosted externally (e.g., on… | Cumple (verificado internamente) | Sin recursos externos (CSP `'self'`) |
| V3.7.1 | L2 | the application only uses client-side technologies which are still supported and considered secure.… | Cumple (verificado internamente) | React 19 y APIs web estándar |
| V3.7.2 | L2 | the application will only automatically redirect the user to a different hostname or domain (which is not… | Cumple (verificado internamente) | No hay redirecciones automáticas |
| V3.7.3 | L3 | the application shows a notification when the user is being redirected to a URL outside of the… | No aplica | No redirige; los enlaces a avisos son clics explícitos del usuario |
| V3.7.4 | L3 | the application's top-level domain (e.g., site.tld) is added to the public preload list for HTTP Strict… | No aplica | Loopback, sin dominio |
| V3.7.5 | L3 | the application behaves as documented (such as warning the user or blocking access) if the browser used to… | No cumple | No detecta navegadores sin soporte de CSP/COOP — L3, fuera del nivel objetivo |

### V4 API and Web Service

| Requisito | Nivel | Resumen oficial | Estado | Evidencia |
|---|---|---|---|---|
| V4.1.1 | L1 | every HTTP response with a message body contains a Content-Type header field that matches the actual… | Cumple (verificado internamente) | `application/json; charset=utf-8` y `text/html; charset=utf-8` (`test_json_declares_its_charset_and_errors_have_one_shape`) |
| V4.1.2 | L2 | only user-facing endpoints (intended for manual web-browser access) automatically redirect from HTTP to… | No aplica | Sin HTTPS en loopback |
| V4.1.3 | L2 | any HTTP header field used by the application and set by an intermediary layer, such as a load balancer, a… | Cumple (verificado internamente) | `proxy_headers=False`: no se confía en `X-Forwarded-*` |
| V4.1.4 | L3 | only HTTP methods that are explicitly supported by the application or its API (including OPTIONS during… | Cumple (verificado internamente) | Métodos no usados → 405 (`test_unused_http_methods_are_refused`) |
| V4.1.5 | L3 | per-message digital signatures are used to provide additional assurance on top of transport protections… | No aplica | No hay transacciones que requieran firma por mensaje |
| V4.2.1 | L2 | all application components (including load balancers, firewalls, and application servers) determine… | Parcial | uvicorn/h11 aplica un parser HTTP/1.1 estricto — No probado por el proyecto: añadir pruebas de request smuggling (CL/TE) |
| V4.2.2 | L3 | when generating HTTP messages, the Content-Length header field does not conflict with the length of the… | Cumple (verificado internamente) | Respuestas generadas por el framework |
| V4.2.3 | L3 | the application does not send nor accept HTTP/2 or HTTP/3 messages with connection-specific header fields… | No aplica | Solo HTTP/1.1 |
| V4.2.4 | L3 | the application only accepts HTTP/2 and HTTP/3 requests where the header fields and values do not contain… | No aplica | Solo HTTP/1.1 |
| V4.2.5 | L3 | Verify that, if the application (backend or frontend) builds and sends requests, it uses validation,… | Cumple (verificado internamente) | Nombres de paquete acotados antes de construir URLs; CVE validados por expresión regular |
| V4.3.1 | L2 | a query allowlist, depth limiting, amount limiting, or query cost analysis is used to prevent GraphQL or… | No aplica | No hay GraphQL. |
| V4.3.2 | L2 | GraphQL introspection queries are disabled in the production environment unless the GraphQL API is meant… | No aplica | No hay GraphQL. |
| V4.4.1 | L1 | WebSocket over TLS (WSS) is used for all WebSocket connections. | No aplica | No hay WebSocket. |
| V4.4.2 | L2 | Verify that, during the initial HTTP WebSocket handshake, the Origin header field is checked against a… | No aplica | No hay WebSocket. |
| V4.4.3 | L2 | Verify that, if the application's standard session management cannot be used, dedicated tokens are being… | No aplica | No hay WebSocket. |
| V4.4.4 | L2 | dedicated WebSocket session management tokens are initially obtained or validated through the previously… | No aplica | No hay WebSocket. |

### V5 File Handling

| Requisito | Nivel | Resumen oficial | Estado | Evidencia |
|---|---|---|---|---|
| V5.1.1 | L2 | the documentation defines the permitted file types, expected file extensions, and maximum size (including… | No aplica | No hay subida de archivos; los límites de lectura están documentados |
| V5.2.1 | L1 | the application will only accept files of a size which it can process without causing a loss of… | No aplica | La aplicación no acepta subida de archivos (lee carpetas locales dentro de las raíces permitidas). |
| V5.2.2 | L1 | when the application accepts a file, either on its own or within an archive such as a zip file, it checks… | No aplica | La aplicación no acepta subida de archivos (lee carpetas locales dentro de las raíces permitidas). |
| V5.2.3 | L2 | the application checks compressed files (e.g., zip, gz, docx, odt) against maximum allowed uncompressed… | No aplica | La aplicación no acepta subida de archivos (lee carpetas locales dentro de las raíces permitidas). |
| V5.2.4 | L3 | a file size quota and maximum number of files per user are enforced to ensure that a single user cannot… | No aplica | La aplicación no acepta subida de archivos (lee carpetas locales dentro de las raíces permitidas). |
| V5.2.5 | L3 | the application does not allow uploading compressed files containing symlinks unless this is specifically… | No aplica | La aplicación no acepta subida de archivos (lee carpetas locales dentro de las raíces permitidas). |
| V5.2.6 | L3 | the application rejects uploaded images with a pixel size larger than the maximum allowed, to prevent… | No aplica | La aplicación no acepta subida de archivos (lee carpetas locales dentro de las raíces permitidas). |
| V5.3.1 | L1 | files uploaded or generated by untrusted input and stored in a public folder, are not executed as… | No aplica | No se sirven archivos de usuario |
| V5.3.2 | L1 | when the application creates file paths for file operations, instead of user-submitted filenames, it uses… | Cumple (verificado internamente) | Raíces permitidas, comprobación léxica y `resolve()`; IDs validados (`test_paths_outside_the_allowed_roots_are_refused`, `test_history_ids_cannot_address_other_files`) |
| V5.3.3 | L3 | server-side file processing, such as file decompression, ignores user-provided path information to prevent… | No aplica | No descomprime archivos |
| V5.4.1 | L2 | the application validates or ignores user-submitted filenames, including in a JSON, JSONP, or URL… | Cumple (verificado internamente) | Nombres de descarga fijos (`EXPORTS` en `server/app.py`) |
| V5.4.2 | L2 | file names served (e.g., in HTTP response header fields or email attachments) are encoded or sanitized… | Cumple (verificado internamente) | Nombres fijos ASCII |
| V5.4.3 | L2 | files obtained from untrusted sources are scanned by antivirus scanners to prevent serving of known… | No aplica | Las descargas son informes generados, no archivos de terceros |

### V6 Authentication

| Requisito | Nivel | Resumen oficial | Estado | Evidencia |
|---|---|---|---|---|
| V6.1.1 | L1 | application documentation defines how controls such as rate limiting, anti-automation, and adaptive… | Cumple (verificado internamente) | Documentado: token de 256 bits (fuerza bruta inviable), sin cuentas que bloquear |
| V6.1.2 | L2 | a list of context-specific words is documented in order to prevent their use in passwords. The list could… | No aplica | No hay contraseñas |
| V6.1.3 | L2 | Verify that, if the application includes multiple authentication pathways, these are all documented… | Cumple (verificado internamente) | Una sola vía de autenticación, documentada |
| V6.2.1 | L1 | user set passwords are at least 8 characters in length although a minimum of 15 characters is strongly… | No aplica | No hay contraseñas ni cuentas de usuario. |
| V6.2.2 | L1 | users can change their password. | No aplica | No hay contraseñas ni cuentas de usuario. |
| V6.2.3 | L1 | password change functionality requires the user's current and new password. | No aplica | No hay contraseñas ni cuentas de usuario. |
| V6.2.4 | L1 | passwords submitted during account registration or password change are checked against an available set… | No aplica | No hay contraseñas ni cuentas de usuario. |
| V6.2.5 | L1 | passwords of any composition can be used, without rules limiting the type of characters permitted. There… | No aplica | No hay contraseñas ni cuentas de usuario. |
| V6.2.6 | L1 | password input fields use type=password to mask the entry. Applications may allow the user to temporarily… | No aplica | No hay contraseñas ni cuentas de usuario. |
| V6.2.7 | L1 | "paste" functionality, browser password helpers, and external password managers are permitted. | No aplica | No hay contraseñas ni cuentas de usuario. |
| V6.2.8 | L1 | the application verifies the user's password exactly as received from the user, without any modifications… | No aplica | No hay contraseñas ni cuentas de usuario. |
| V6.2.9 | L2 | passwords of at least 64 characters are permitted. | No aplica | No hay contraseñas ni cuentas de usuario. |
| V6.2.10 | L2 | a user's password stays valid until it is discovered to be compromised or the user rotates it. The… | No aplica | No hay contraseñas ni cuentas de usuario. |
| V6.2.11 | L2 | the documented list of context specific words is used to prevent easy to guess passwords being created. | No aplica | No hay contraseñas ni cuentas de usuario. |
| V6.2.12 | L2 | passwords submitted during account registration or password changes are checked against a set of breached… | No aplica | No hay contraseñas ni cuentas de usuario. |
| V6.3.1 | L1 | controls to prevent attacks such as credential stuffing and password brute force are implemented according… | Cumple (verificado internamente) | Justificación documentada: 2^256 combinaciones; los fallos se registran |
| V6.3.2 | L1 | default user accounts (e.g., "root", "admin", or "sa") are not present in the application or are disabled. | Cumple (verificado internamente) | No hay cuentas |
| V6.3.3 | L2 | either a multi-factor authentication mechanism or a combination of single-factor authentication… | Parcial | Un factor: posesión del token impreso en la terminal del usuario — Desviación documentada: herramienta local monousuario en loopback |
| V6.3.4 | L2 | Verify that, if the application includes multiple authentication pathways, there are no undocumented… | Cumple (verificado internamente) | Una sola vía |
| V6.3.5 | L3 | users are notified of suspicious authentication attempts (successful or unsuccessful). This may include… | No aplica | No hay cuentas |
| V6.3.6 | L3 | email is not used as either a single-factor or multi-factor authentication mechanism. | No aplica | No se usa correo |
| V6.3.7 | L3 | users are notified after updates to authentication details, such as credential resets or modification of… | No aplica | No hay datos de autenticación modificables |
| V6.3.8 | L3 | valid users cannot be deduced from failed authentication challenges, such as by basing on error messages,… | No aplica | No hay usuarios que enumerar |
| V6.4.1 | L1 | system generated initial passwords or activation codes are securely randomly generated, follow the… | No aplica | No hay factores de autenticación con ciclo de vida ni recuperación. |
| V6.4.2 | L1 | password hints or knowledge-based authentication (so-called "secret questions") are not present. | No aplica | No hay factores de autenticación con ciclo de vida ni recuperación. |
| V6.4.3 | L2 | a secure process for resetting a forgotten password is implemented, that does not bypass any enabled… | No aplica | No hay factores de autenticación con ciclo de vida ni recuperación. |
| V6.4.4 | L2 | if a multi-factor authentication factor is lost, evidence of identity proofing is performed at the same… | No aplica | No hay factores de autenticación con ciclo de vida ni recuperación. |
| V6.4.5 | L3 | renewal instructions for authentication mechanisms which expire are sent with enough time to be carried… | No aplica | No hay factores de autenticación con ciclo de vida ni recuperación. |
| V6.4.6 | L3 | administrative users can initiate the password reset process for the user, but that this does not allow… | No aplica | No hay factores de autenticación con ciclo de vida ni recuperación. |
| V6.5.1 | L2 | lookup secrets, out-of-band authentication requests or codes, and time-based one-time passwords (TOTPs)… | No aplica | No hay MFA (ver V6.3.3). |
| V6.5.2 | L2 | Verify that, when being stored in the application's backend, lookup secrets with less than 112 bits of… | No aplica | No hay MFA (ver V6.3.3). |
| V6.5.3 | L2 | lookup secrets, out-of-band authentication code, and time-based one-time password seeds, are generated… | No aplica | No hay MFA (ver V6.3.3). |
| V6.5.4 | L2 | lookup secrets and out-of-band authentication codes have a minimum of 20 bits of entropy (typically 4… | No aplica | No hay MFA (ver V6.3.3). |
| V6.5.5 | L2 | out-of-band authentication requests, codes, or tokens, as well as time-based one-time passwords (TOTPs)… | No aplica | No hay MFA (ver V6.3.3). |
| V6.5.6 | L3 | any authentication factor (including physical devices) can be revoked in case of theft or other loss. | No aplica | No hay MFA (ver V6.3.3). |
| V6.5.7 | L3 | biometric authentication mechanisms are only used as secondary factors together with either something you… | No aplica | No hay MFA (ver V6.3.3). |
| V6.5.8 | L3 | time-based one-time passwords (TOTPs) are checked based on a time source from a trusted service and not… | No aplica | No hay MFA (ver V6.3.3). |
| V6.6.1 | L2 | authentication mechanisms using the Public Switched Telephone Network (PSTN) to deliver One-time Passwords… | No aplica | No hay autenticación fuera de banda. |
| V6.6.2 | L2 | out-of-band authentication requests, codes, or tokens are bound to the original authentication request for… | No aplica | No hay autenticación fuera de banda. |
| V6.6.3 | L2 | a code based out-of-band authentication mechanism is protected against brute force attacks by using rate… | No aplica | No hay autenticación fuera de banda. |
| V6.6.4 | L3 | Verify that, where push notifications are used for multi-factor authentication, rate limiting is used to… | No aplica | No hay autenticación fuera de banda. |
| V6.7.1 | L3 | the certificates used to verify cryptographic authentication assertions are stored in a way protects them… | No aplica | No hay autenticación criptográfica de usuarios. |
| V6.7.2 | L3 | the challenge nonce is at least 64 bits in length, and statistically unique or unique over the lifetime of… | No aplica | No hay autenticación criptográfica de usuarios. |
| V6.8.1 | L2 | Verify that, if the application supports multiple identity providers (IdPs), the user's identity cannot be… | No aplica | No hay proveedor de identidad. |
| V6.8.2 | L2 | the presence and integrity of digital signatures on authentication assertions (for example on JWTs or SAML… | No aplica | No hay proveedor de identidad. |
| V6.8.3 | L2 | SAML assertions are uniquely processed and used only once within the validity period to prevent replay… | No aplica | No hay proveedor de identidad. |
| V6.8.4 | L2 | Verify that, if an application uses a separate Identity Provider (IdP) and expects specific authentication… | No aplica | No hay proveedor de identidad. |

### V7 Session Management

| Requisito | Nivel | Resumen oficial | Estado | Evidencia |
|---|---|---|---|---|
| V7.1.1 | L2 | the user's session inactivity timeout and absolute maximum session lifetime are documented, are… | Cumple (verificado internamente) | 60 min de inactividad y 12 h absolutas, documentadas (`docs/security.md` §3) |
| V7.1.2 | L2 | the documentation defines how many concurrent (parallel) sessions are allowed for one account as well as… | Cumple (verificado internamente) | Documentado: un token por proceso, compartido por las pestañas del usuario |
| V7.1.3 | L2 | all systems that create and manage user sessions as part of a federated identity management ecosystem… | No aplica | Sin SSO |
| V7.2.1 | L1 | the application performs all session token verification using a trusted, backend service. | Cumple (verificado internamente) | Verificación en el backend (`server/app.py`) |
| V7.2.2 | L1 | the application uses either self-contained or reference tokens that are dynamically generated for session… | Cumple (verificado internamente) | Token dinámico por arranque |
| V7.2.3 | L1 | if reference tokens are used to represent user sessions, they are unique and generated using a… | Cumple (verificado internamente) | `secrets.token_urlsafe(32)`: 256 bits de CSPRNG |
| V7.2.4 | L1 | the application generates a new session token on user authentication, including re-authentication, and… | Cumple (verificado internamente) | Cada arranque genera un token nuevo; no hay reautenticación dentro del proceso |
| V7.3.1 | L2 | there is an inactivity timeout such that re-authentication is enforced according to risk analysis and… | Cumple (verificado internamente) | `test_session_expires_after_inactivity` |
| V7.3.2 | L2 | there is an absolute maximum session lifetime such that re-authentication is enforced according to risk… | Cumple (verificado internamente) | `test_session_has_an_absolute_lifetime` |
| V7.4.1 | L1 | when session termination is triggered (such as logout or expiration), the application disallows any… | Cumple (verificado internamente) | `test_ending_the_session_revokes_the_token` |
| V7.4.2 | L1 | the application terminates all active sessions when a user account is disabled or deleted (such as an… | No aplica | No hay cuentas |
| V7.4.3 | L2 | the application gives the option to terminate all other active sessions after a successful change or… | No aplica | No hay factores modificables |
| V7.4.4 | L2 | all pages that require authentication have easy and visible access to logout functionality. | Cumple (verificado internamente) | Botón «Cerrar sesión» (e2e `ending the session revokes the token…`) |
| V7.4.5 | L2 | application administrators are able to terminate active sessions for an individual user or for all users. | No aplica | No hay administradores; detener el proceso termina la sesión |
| V7.5.1 | L2 | the application requires full re-authentication before allowing modifications to sensitive account… | No aplica | No hay atributos de cuenta |
| V7.5.2 | L2 | users are able to view and (having authenticated again with at least one factor) terminate any or all… | No aplica | Una sola sesión por proceso |
| V7.5.3 | L3 | the application requires further authentication with at least one factor or secondary verification before… | No aplica | No hay operaciones de alta sensibilidad más allá de leer las raíces permitidas |
| V7.6.1 | L2 | session lifetime and termination between Relying Parties (RPs) and Identity Providers (IdPs) behave as… | No aplica | No hay identidad federada. |
| V7.6.2 | L2 | creation of a session requires either the user's consent or an explicit action, preventing the creation of… | No aplica | No hay identidad federada. |

### V8 Authorization

| Requisito | Nivel | Resumen oficial | Estado | Evidencia |
|---|---|---|---|---|
| V8.1.1 | L1 | authorization documentation defines rules for restricting function-level and data-specific access based on… | Cumple (verificado internamente) | Documentado: todo `/api` exige token; los datos se limitan a las raíces |
| V8.1.2 | L2 | authorization documentation defines rules for field-level access restrictions (both read and write) based… | No aplica | No hay autorización por campo |
| V8.1.3 | L3 | the application's documentation defines the environmental and contextual attributes (including but not… | Cumple (verificado internamente) | Atributos de contexto documentados: Host, Origin, Sec-Fetch-Site, loopback |
| V8.1.4 | L3 | authentication and authorization documentation defines how environmental and contextual factors are used… | Cumple (verificado internamente) | Documentado en `docs/security.md` §3 (acción: denegar) |
| V8.2.1 | L1 | the application ensures that function-level access is restricted to consumers with explicit permissions. | Cumple (verificado internamente) | Middleware único para todo `/api` |
| V8.2.2 | L1 | the application ensures that data-specific access is restricted to consumers with explicit permissions to… | Cumple (verificado internamente) | Raíces permitidas e IDs validados (IDOR sobre rutas) |
| V8.2.3 | L2 | the application ensures that field-level access is restricted to consumers with explicit permissions to… | No aplica | No hay campos con permisos distintos |
| V8.2.4 | L3 | adaptive security controls based on a consumer's environmental and contextual attributes (such as time of… | Cumple (verificado internamente) | Host/Origin/Sec-Fetch evaluados en cada petición |
| V8.3.1 | L1 | the application enforces authorization rules at a trusted service layer and doesn't rely on controls that… | Cumple (verificado internamente) | En el backend |
| V8.3.2 | L3 | changes to values on which authorization decisions are made are applied immediately. Where changes cannot… | Cumple (verificado internamente) | Cierre de sesión y caducidad efectivos en la siguiente petición |
| V8.3.3 | L3 | access to an object is based on the originating subject's (e.g. consumer's) permissions, not on the… | No aplica | No hay servicios intermedios |
| V8.4.1 | L2 | multi-tenant applications use cross-tenant controls to ensure consumer operations will never affect… | No aplica | No es multi-tenant |
| V8.4.2 | L3 | access to administrative interfaces incorporates multiple layers of security, including continuous… | No aplica | No hay interfaz de administración |

### V9 Self-contained Tokens

| Requisito | Nivel | Resumen oficial | Estado | Evidencia |
|---|---|---|---|---|
| V9.1.1 | L1 | self-contained tokens are validated using their digital signature or MAC to protect against tampering… | No aplica | El token es una referencia opaca aleatoria, no un token autocontenido (JWT). |
| V9.1.2 | L1 | only algorithms on an allowlist can be used to create and verify self-contained tokens, for a given… | No aplica | El token es una referencia opaca aleatoria, no un token autocontenido (JWT). |
| V9.1.3 | L1 | key material that is used to validate self-contained tokens is from trusted pre-configured sources for the… | No aplica | El token es una referencia opaca aleatoria, no un token autocontenido (JWT). |
| V9.2.1 | L1 | Verify that, if a validity time span is present in the token data, the token and its content are accepted… | No aplica | El token es una referencia opaca aleatoria, no un token autocontenido (JWT). |
| V9.2.2 | L2 | the service receiving a token validates the token to be the correct type and is meant for the intended… | No aplica | El token es una referencia opaca aleatoria, no un token autocontenido (JWT). |
| V9.2.3 | L2 | the service only accepts tokens which are intended for use with that service (audience). For JWTs, this… | No aplica | El token es una referencia opaca aleatoria, no un token autocontenido (JWT). |
| V9.2.4 | L2 | Verify that, if a token issuer uses the same private key for issuing tokens to different audiences, the… | No aplica | El token es una referencia opaca aleatoria, no un token autocontenido (JWT). |

### V10 OAuth and OIDC

| Requisito | Nivel | Resumen oficial | Estado | Evidencia |
|---|---|---|---|---|
| V10.1.1 | L2 | tokens are only sent to components that strictly need them. For example, when using a backend-for-frontend… | No aplica | No se usa OAuth ni OIDC. |
| V10.1.2 | L2 | the client only accepts values from the authorization server (such as the authorization code or ID Token)… | No aplica | No se usa OAuth ni OIDC. |
| V10.2.1 | L2 | Verify that, if the code flow is used, the OAuth client has protection against browser-based request… | No aplica | No se usa OAuth ni OIDC. |
| V10.2.2 | L2 | Verify that, if the OAuth client can interact with more than one authorization server, it has a defense… | No aplica | No se usa OAuth ni OIDC. |
| V10.2.3 | L3 | the OAuth client only requests the required scopes (or other authorization parameters) in requests to the… | No aplica | No se usa OAuth ni OIDC. |
| V10.3.1 | L2 | the resource server only accepts access tokens that are intended for use with that service (audience). The… | No aplica | No se usa OAuth ni OIDC. |
| V10.3.2 | L2 | the resource server enforces authorization decisions based on claims from the access token that define… | No aplica | No se usa OAuth ni OIDC. |
| V10.3.3 | L2 | if an access control decision requires identifying a unique user from an access token (JWT or related… | No aplica | No se usa OAuth ni OIDC. |
| V10.3.4 | L2 | Verify that, if the resource server requires specific authentication strength, methods, or recentness, it… | No aplica | No se usa OAuth ni OIDC. |
| V10.3.5 | L3 | the resource server prevents the use of stolen access tokens or replay of access tokens (from unauthorized… | No aplica | No se usa OAuth ni OIDC. |
| V10.4.1 | L1 | the authorization server validates redirect URIs based on a client-specific allowlist of pre-registered… | No aplica | No se usa OAuth ni OIDC. |
| V10.4.2 | L1 | Verify that, if the authorization server returns the authorization code in the authorization response, it… | No aplica | No se usa OAuth ni OIDC. |
| V10.4.3 | L1 | the authorization code is short-lived. The maximum lifetime can be up to 10 minutes for L1 and L2… | No aplica | No se usa OAuth ni OIDC. |
| V10.4.4 | L1 | for a given client, the authorization server only allows the usage of grants that this client needs to… | No aplica | No se usa OAuth ni OIDC. |
| V10.4.5 | L1 | the authorization server mitigates refresh token replay attacks for public clients, preferably using… | No aplica | No se usa OAuth ni OIDC. |
| V10.4.6 | L2 | Verify that, if the code grant is used, the authorization server mitigates authorization code interception… | No aplica | No se usa OAuth ni OIDC. |
| V10.4.7 | L2 | if the authorization server supports unauthenticated dynamic client registration, it mitigates the risk of… | No aplica | No se usa OAuth ni OIDC. |
| V10.4.8 | L2 | refresh tokens have an absolute expiration, including if sliding refresh token expiration is applied. | No aplica | No se usa OAuth ni OIDC. |
| V10.4.9 | L2 | refresh tokens and reference access tokens can be revoked by an authorized user using the authorization… | No aplica | No se usa OAuth ni OIDC. |
| V10.4.10 | L2 | confidential client is authenticated for client-to-authorized server backchannel requests such as token… | No aplica | No se usa OAuth ni OIDC. |
| V10.4.11 | L2 | the authorization server configuration only assigns the required scopes to the OAuth client. | No aplica | No se usa OAuth ni OIDC. |
| V10.4.12 | L3 | for a given client, the authorization server only allows the 'response_mode' value that this client needs… | No aplica | No se usa OAuth ni OIDC. |
| V10.4.13 | L3 | grant type 'code' is always used together with pushed authorization requests (PAR). | No aplica | No se usa OAuth ni OIDC. |
| V10.4.14 | L3 | the authorization server issues only sender-constrained (Proof-of-Possession) access tokens, either with… | No aplica | No se usa OAuth ni OIDC. |
| V10.4.15 | L3 | Verify that, for a server-side client (which is not executed on the end-user device), the authorization… | No aplica | No se usa OAuth ni OIDC. |
| V10.4.16 | L3 | the client is confidential and the authorization server requires the use of strong client authentication… | No aplica | No se usa OAuth ni OIDC. |
| V10.5.1 | L2 | the client (as the relying party) mitigates ID Token replay attacks. For example, by ensuring that the… | No aplica | No se usa OAuth ni OIDC. |
| V10.5.2 | L2 | the client uniquely identifies the user from ID Token claims, usually the 'sub' claim, which cannot be… | No aplica | No se usa OAuth ni OIDC. |
| V10.5.3 | L2 | the client rejects attempts by a malicious authorization server to impersonate another authorization… | No aplica | No se usa OAuth ni OIDC. |
| V10.5.4 | L2 | the client validates that the ID Token is intended to be used for that client (audience) by checking that… | No aplica | No se usa OAuth ni OIDC. |
| V10.5.5 | L2 | Verify that, when using OIDC back-channel logout, the relying party mitigates denial of service through… | No aplica | No se usa OAuth ni OIDC. |
| V10.6.1 | L2 | the OpenID Provider only allows values 'code', 'ciba', 'id_token', or 'id_token code' for response mode.… | No aplica | No se usa OAuth ni OIDC. |
| V10.6.2 | L2 | the OpenID Provider mitigates denial of service through forced logout. By obtaining explicit confirmation… | No aplica | No se usa OAuth ni OIDC. |
| V10.7.1 | L2 | the authorization server ensures that the user consents to each authorization request. If the identity of… | No aplica | No se usa OAuth ni OIDC. |
| V10.7.2 | L2 | when the authorization server prompts for user consent, it presents sufficient and clear information about… | No aplica | No se usa OAuth ni OIDC. |
| V10.7.3 | L2 | the user can review, modify, and revoke consents which the user has granted through the authorization server. | No aplica | No se usa OAuth ni OIDC. |

### V11 Cryptography

| Requisito | Nivel | Resumen oficial | Estado | Evidencia |
|---|---|---|---|---|
| V11.1.1 | L2 | there is a documented policy for management of cryptographic keys and a cryptographic key lifecycle that… | No aplica | No hay claves gestionadas (el token es efímero en memoria) |
| V11.1.2 | L2 | a cryptographic inventory is performed, maintained, regularly updated, and includes all cryptographic… | Cumple (verificado internamente) | Inventario criptográfico (`docs/security.md` §5) |
| V11.1.3 | L3 | cryptographic discovery mechanisms are employed to identify all instances of cryptography in the system,… | Parcial | Inventario por revisión de código y búsqueda — Sin herramienta de descubrimiento criptográfico automatizada |
| V11.1.4 | L3 | a cryptographic inventory is maintained. This must include a documented plan that outlines the migration… | No aplica | No implementa criptografía propia; TLS y firmas los proveen la plataforma y Sigstore |
| V11.2.1 | L2 | industry-validated implementations (including libraries and hardware-accelerated implementations) are used… | Cumple (verificado internamente) | `secrets`, `hmac`, `hashlib`, `ssl` de la biblioteca estándar |
| V11.2.2 | L2 | the application is designed with crypto agility such that random number, authenticated encryption, MAC, or… | No aplica | No hay operaciones criptográficas configurables |
| V11.2.3 | L2 | all cryptographic primitives utilize a minimum of 128-bits of security based on the algorithm, key size,… | Cumple (verificado internamente) | Token de 256 bits |
| V11.2.4 | L3 | all cryptographic operations are constant-time, with no 'short-circuit' operations in comparisons,… | Cumple (verificado internamente) | `hmac.compare_digest` |
| V11.2.5 | L3 | all cryptographic modules fail securely, and errors are handled in a way that does not enable… | No aplica | No hay módulos de cifrado |
| V11.3.1 | L1 | insecure block modes (e.g., ECB) and weak padding schemes (e.g., PKCS#1 v1.5) are not used. | No aplica | DepGuard no cifra datos. |
| V11.3.2 | L1 | only approved ciphers and modes such as AES with GCM are used. | No aplica | DepGuard no cifra datos. |
| V11.3.3 | L2 | encrypted data is protected against unauthorized modification preferably by using an approved… | No aplica | DepGuard no cifra datos. |
| V11.3.4 | L3 | nonces, initialization vectors, and other single-use numbers are not used for more than one encryption key… | No aplica | DepGuard no cifra datos. |
| V11.3.5 | L3 | any combination of an encryption algorithm and a MAC algorithm is operating in encrypt-then-MAC mode. | No aplica | DepGuard no cifra datos. |
| V11.4.1 | L1 | only approved hash functions are used for general cryptographic use cases, including digital signatures,… | Cumple (verificado internamente) | Solo SHA-256 |
| V11.4.2 | L2 | passwords are stored using an approved, computationally intensive, key derivation function (also known as… | No aplica | No hay contraseñas |
| V11.4.3 | L2 | hash functions used in digital signatures, as part of data authentication or data integrity are collision… | Cumple (verificado internamente) | SHA-256 para `SHA256SUMS` y sellos de informes |
| V11.4.4 | L2 | the application uses approved key derivation functions with key stretching parameters when deriving secret… | No aplica | No se derivan claves de contraseñas |
| V11.5.1 | L2 | all random numbers and strings which are intended to be non-guessable must be generated using a… | Cumple (verificado internamente) | `secrets` (CSPRNG); los IDs de historial (64 bits) no son secretos |
| V11.5.2 | L3 | the random number generation mechanism in use is designed to work securely, even under heavy demand. | Cumple (verificado internamente) | `secrets` usa el CSPRNG del sistema operativo |
| V11.6.1 | L2 | only approved cryptographic algorithms and modes of operation are used for key generation and seeding, and… | No aplica | No usa criptografía de clave pública propia (las firmas de release las hace Sigstore en CI). |
| V11.6.2 | L3 | approved cryptographic algorithms are used for key exchange (such as Diffie-Hellman) with a focus on… | No aplica | No usa criptografía de clave pública propia (las firmas de release las hace Sigstore en CI). |
| V11.7.1 | L3 | full memory encryption is in use that protects sensitive data while it is in use, preventing access by… | No aplica | No protege datos en uso con criptografía. |
| V11.7.2 | L3 | data minimization ensures the minimal amount of data is exposed during processing, and ensure that data is… | No aplica | No protege datos en uso con criptografía. |

### V12 Secure Communication

| Requisito | Nivel | Resumen oficial | Estado | Evidencia |
|---|---|---|---|---|
| V12.1.1 | L1 | only the latest recommended versions of the TLS protocol are enabled, such as TLS 1.2 and TLS 1.3. The… | No aplica | No hay servidor TLS (loopback) |
| V12.1.2 | L2 | only recommended cipher suites are enabled, with the strongest cipher suites set as preferred. L3… | No aplica | No hay servidor TLS |
| V12.1.3 | L2 | the application validates that mTLS client certificates are trusted before using the certificate identity… | No aplica | Sin mTLS |
| V12.1.4 | L3 | proper certification revocation, such as Online Certificate Status Protocol (OCSP) Stapling, is enabled… | No aplica | No hay servidor TLS |
| V12.1.5 | L3 | Encrypted Client Hello (ECH) is enabled in the application's TLS settings to prevent exposure of sensitive… | No aplica | No hay servidor TLS |
| V12.2.1 | L1 | TLS is used for all connectivity between a client and external facing, HTTP-based services, and does not… | No aplica | No es un servicio expuesto (solo `127.0.0.1`) |
| V12.2.2 | L1 | external facing services use publicly trusted TLS certificates. | No aplica | No es un servicio expuesto |
| V12.3.1 | L2 | an encrypted protocol such as TLS is used for all inbound and outbound connections to and from the… | Parcial | Todas las conexiones salientes por HTTPS sin degradación — La conexión navegador↔servidor es HTTP en loopback (no sale del equipo): desviación documentada |
| V12.3.2 | L2 | TLS clients validate certificates received before communicating with a TLS server. | Cumple (verificado internamente) | `httpx` verifica certificados (nunca `verify=False`) |
| V12.3.3 | L2 | TLS or another appropriate transport encryption mechanism used for all connectivity between internal,… | No aplica | No hay servicios internos |
| V12.3.4 | L2 | TLS connections between internal services use trusted certificates. Where internally generated or… | No aplica | No hay servicios internos |
| V12.3.5 | L3 | services communicating internally within a system (intra-service communications) use strong authentication… | No aplica | No hay servicios internos |

### V13 Configuration

| Requisito | Nivel | Resumen oficial | Estado | Evidencia |
|---|---|---|---|---|
| V13.1.1 | L2 | all communication needs for the application are documented. This must include external services which the… | Cumple (verificado internamente) | Hosts y motivos documentados (`docs/security.md` §2) |
| V13.1.2 | L3 | for each service the application uses, the documentation defines the maximum number of concurrent… | Cumple (verificado internamente) | 16 conexiones simultáneas y comportamiento documentados |
| V13.1.3 | L3 | the application documentation defines resource‑management strategies for every external system or service… | Cumple (verificado internamente) | Timeouts, reintentos y backoff documentados (`docs/security.md` §2) |
| V13.1.4 | L3 | the application's documentation defines the secrets that are critical for the security of the application… | Cumple (verificado internamente) | Secretos documentados: token (rota en cada arranque, 12 h) y `NVD_API_KEY` (del usuario) |
| V13.2.1 | L2 | communications between backend application components that don't support the application's standard user… | No aplica | No hay componentes backend separados |
| V13.2.2 | L2 | communications between backend application components, including local or operating system services, APIs,… | No aplica | No hay componentes backend separados |
| V13.2.3 | L2 | if a credential has to be used for service authentication, the credential being used by the consumer is… | No aplica | No hay credenciales de servicio |
| V13.2.4 | L2 | an allowlist is used to define the external resources or systems with which the application is permitted… | Cumple (verificado internamente) | `ALLOWED_HOSTS` y raíces permitidas |
| V13.2.5 | L2 | the web or application server is configured with an allowlist of resources or systems to which the server… | Cumple (verificado internamente) | `ALLOWED_HOSTS` aplicado en cada petición saliente |
| V13.2.6 | L3 | where the application connects to separate services, it follows the documented configuration for each… | Cumple (verificado internamente) | Configuración por conexión documentada y aplicada |
| V13.3.1 | L2 | a secrets management solution, such as a key vault, is used to securely create, store, control access to,… | Parcial | Ningún secreto en código ni artefactos (gitleaks sobre todo el historial) — No hay gestor de secretos: `NVD_API_KEY` se lee de una variable de entorno (herramienta local) |
| V13.3.2 | L2 | access to secret assets adheres to the principle of least privilege. | Cumple (verificado internamente) | El token solo lo conoce el proceso y el usuario |
| V13.3.3 | L3 | all cryptographic operations are performed using an isolated security module (such as a vault or hardware… | No aplica | No hay operaciones criptográficas con claves (L3) |
| V13.3.4 | L3 | secrets are configured to expire and be rotated based on the application's documentation. | Cumple (verificado internamente) | El token rota en cada arranque y caduca en 12 h |
| V13.4.1 | L1 | the application is deployed either without any source control metadata, including the .git or .svn… | Cumple (verificado internamente) | Solo se sirve `dep_guard/server/static` |
| V13.4.2 | L2 | debug modes are disabled for all components in production environments to prevent exposure of debugging… | Cumple (verificado internamente) | Sin modo debug; documentación desactivada; errores genéricos |
| V13.4.3 | L2 | web servers do not expose directory listings to clients unless explicitly intended. | Cumple (verificado internamente) | `StaticFiles` sin listado de directorios; `/api/browse` lista carpetas a propósito, autenticado y dentro de raíces |
| V13.4.4 | L2 | using the HTTP TRACE method is not supported in production environments, to avoid potential information… | Cumple (verificado internamente) | TRACE → 405 (`test_unused_http_methods_are_refused`) |
| V13.4.5 | L2 | documentation (such as for internal APIs) and monitoring endpoints are not exposed unless explicitly intended. | Cumple (verificado internamente) | `/docs`, `/redoc`, `/openapi.json` → 404 |
| V13.4.6 | L3 | the application does not expose detailed version information of backend components. | Parcial | Sin cabecera `Server` — `/api/info` devuelve la versión de DepGuard al usuario autenticado (intencionado) |
| V13.4.7 | L3 | the web tier is configured to only serve files with specific file extensions to prevent unintentional… | Cumple (verificado internamente) | Solo la carpeta de build de la interfaz |

### V14 Data Protection

| Requisito | Nivel | Resumen oficial | Estado | Evidencia |
|---|---|---|---|---|
| V14.1.1 | L2 | all sensitive data created and processed by the application has been identified and classified into… | Cumple (verificado internamente) | Clasificación de datos (`docs/security.md` §4) |
| V14.1.2 | L2 | all sensitive data protection levels have a documented set of protection requirements. This must include… | Cumple (verificado internamente) | Requisitos de protección por dato (`docs/security.md` §4) |
| V14.2.1 | L1 | sensitive data is only sent to the server in the HTTP message body or header fields, and that the URL and… | Parcial | El token llega una vez en el fragmento `#token=` (no se envía al servidor ni en Referer) y se retira de la barra de direcciones — Queda en el historial local del navegador hasta caducar (RR-06). Mejora: intercambio por código de un solo uso |
| V14.2.2 | L2 | the application prevents sensitive data from being cached in server components, such as load balancers and… | Cumple (verificado internamente) | `Cache-Control: no-store` en la API; sin cachés intermedias |
| V14.2.3 | L2 | defined sensitive data is not sent to untrusted parties (e.g., user trackers) to prevent unwanted… | Cumple (verificado internamente) | Solo ecosistema, nombre y versión a las fuentes documentadas; `private_packages` |
| V14.2.4 | L2 | controls around sensitive data related to encryption, integrity verification, retention, how the data is… | Cumple (verificado internamente) | Historial local limitado y borrable; token nunca en logs |
| V14.2.5 | L3 | caching mechanisms are configured to only cache responses which have the expected content type for that… | Cumple (verificado internamente) | 404 para archivos estáticos inexistentes |
| V14.2.6 | L3 | the application only returns the minimum required sensitive data for the application's functionality. For… | Cumple (verificado internamente) | Informes con rutas relativas |
| V14.2.7 | L3 | sensitive information is subject to data retention classification, ensuring that outdated or unnecessary… | Parcial | Historial limitado a 50 entradas — Sin caducidad temporal automática |
| V14.2.8 | L3 | sensitive information is removed from the metadata of user-submitted files unless storage is consented to… | No aplica | No hay archivos subidos |
| V14.3.1 | L1 | authenticated data is cleared from client storage, such as the browser DOM, after the client or session is… | Cumple (verificado internamente) | «Cerrar sesión» borra `sessionStorage` (e2e) |
| V14.3.2 | L2 | the application sets sufficient anti-caching HTTP response header fields (i.e., Cache-Control: no-store)… | Cumple (verificado internamente) | `no-store` en la API |
| V14.3.3 | L2 | data stored in browser storage (such as localStorage, sessionStorage, IndexedDB, or cookies) does not… | Cumple (verificado internamente) | Solo el token en `sessionStorage`; el tema visual en `localStorage` |

### V15 Secure Coding and Architecture

| Requisito | Nivel | Resumen oficial | Estado | Evidencia |
|---|---|---|---|---|
| V15.1.1 | L1 | application documentation defines risk based remediation time frames for 3rd party component versions with… | Cumple (verificado internamente) | Plazos de corrección en `SECURITY.md` |
| V15.1.2 | L2 | an inventory catalog, such as software bill of materials (SBOM), is maintained of all third-party… | Cumple (verificado internamente) | SBOM CycloneDX y SPDX de DepGuard en CI y en cada release |
| V15.1.3 | L2 | the application documentation identifies functionality which is time-consuming or resource-demanding. This… | Cumple (verificado internamente) | Análisis costoso documentado: uno a la vez, timeout |
| V15.1.4 | L3 | application documentation highlights third-party libraries which are considered to be "risky components". | Cumple (verificado internamente) | Componentes de riesgo documentados (`docs/security.md` §3) |
| V15.1.5 | L3 | application documentation highlights parts of the application where "dangerous functionality" is being used. | Cumple (verificado internamente) | Funcionalidad sensible documentada (`docs/security.md` §3) |
| V15.2.1 | L1 | the application only contains components which have not breached the documented update and remediation… | Cumple (verificado internamente) | 0 vulnerabilidades conocidas (DepGuard, OSV-Scanner, npm audit, 2026-11-18) |
| V15.2.2 | L2 | the application has implemented defenses against loss of availability due to functionality which is… | Cumple (verificado internamente) | Defensas implementadas (ver V2.4.1) |
| V15.2.3 | L2 | the production environment only includes functionality that is required for the application to function,… | Cumple (verificado internamente) | El wheel solo contiene `dep_guard/` (tests y fixtures solo en el sdist) |
| V15.2.4 | L3 | third-party components and all of their transitive dependencies are included from the expected repository,… | Cumple (verificado internamente) | Lock con hashes; registro npm oficial fijado (`web/.npmrc`) |
| V15.2.5 | L3 | the application implements additional protections around parts of the application which are documented as… | Parcial | Parsers y servidor en el mismo proceso — Sin sandbox para los parsers de formatos no confiables |
| V15.3.1 | L1 | the application only returns the required subset of fields from a data object. For example, it should not… | Cumple (verificado internamente) | Respuestas con los campos necesarios |
| V15.3.2 | L2 | where the application backend makes calls to external URLs, it is configured to not follow redirects… | Cumple (verificado internamente) | `follow_redirects=False` |
| V15.3.3 | L2 | the application has countermeasures to protect against mass assignment attacks by limiting allowed fields… | Cumple (verificado internamente) | `extra=forbid` (test) |
| V15.3.4 | L2 | all proxying and middleware components transfer the user's original IP address correctly using trusted… | Cumple (verificado internamente) | `proxy_headers=False` |
| V15.3.5 | L2 | the application explicitly ensures that variables are of the correct type and performs strict equality and… | Cumple (verificado internamente) | mypy `--strict`; `pydantic` con `strict=True` (test con `"latest": 1`) |
| V15.3.6 | L2 | JavaScript code is written in a way that prevents prototype pollution, for example, by using Set() or… | Cumple (verificado internamente) | Test `untrusted keys never pollute prototypes` |
| V15.3.7 | L2 | the application has defenses against HTTP parameter pollution attacks, particularly if the application… | Cumple (verificado internamente) | Un único parámetro de consulta tipado; cuerpo JSON estricto |
| V15.4.1 | L3 | shared objects in multi-threaded code (such as caches, files, or in-memory objects accessed by multiple… | Cumple (verificado internamente) | Historial con `threading.Lock`; bandera de ocupado liberada por el hilo |
| V15.4.2 | L3 | checks on a resource's state, such as its existence or permissions, and the actions that depend on them… | Parcial | Validación de ruta y lectura no atómicas — TOCTOU con enlaces requiere escritura local del mismo usuario (RR-04) |
| V15.4.3 | L3 | locks are used consistently to avoid threads getting stuck, whether by waiting on each other or retrying… | Cumple (verificado internamente) | Un solo lock por recurso, sin anidamiento |
| V15.4.4 | L3 | resource allocation policies prevent thread starvation by ensuring fair access to resources, such as by… | Cumple (verificado internamente) | `limit_concurrency` de uvicorn y un análisis a la vez |

### V16 Security Logging and Error Handling

| Requisito | Nivel | Resumen oficial | Estado | Evidencia |
|---|---|---|---|---|
| V16.1.1 | L2 | an inventory exists documenting the logging performed at each layer of the application's technology stack,… | Cumple (verificado internamente) | Inventario de registro (`docs/security.md` §6) |
| V16.2.1 | L2 | each log entry includes necessary metadata (such as when, where, who, what) that would allow for a… | Cumple (verificado internamente) | Fecha UTC, motivo, método, ruta y cliente |
| V16.2.2 | L2 | time sources for all logging components are synchronized, and that timestamps in security event metadata… | Cumple (verificado internamente) | UTC ISO-8601 |
| V16.2.3 | L2 | the application only stores or broadcasts logs to the files and services that are documented in the log… | Cumple (verificado internamente) | Solo `stderr`, documentado |
| V16.2.4 | L2 | logs can be read and correlated by the log processor that is in use, preferably by using a common logging… | Cumple (verificado internamente) | Formato clave=valor de una línea |
| V16.2.5 | L2 | when logging sensitive data, the application enforces logging based on the data's protection level. For… | Cumple (verificado internamente) | El token nunca se registra (`test_security_events_are_logged_without_secrets`) |
| V16.3.1 | L2 | all authentication operations are logged, including successful and unsuccessful attempts. Additional… | Parcial | Fallos de autenticación registrados — Los aciertos no se registran por petición (cada llamada se autentica); solo se anuncia el inicio de sesión |
| V16.3.2 | L2 | failed authorization attempts are logged. For L3, this must include logging all authorization decisions,… | Cumple (verificado internamente) | Rutas fuera de raíces y sesiones caducadas registradas |
| V16.3.3 | L2 | the application logs the security events that are defined in the documentation and also logs attempts to… | Cumple (verificado internamente) | Host, Origin, Sec-Fetch y tamaño registrados |
| V16.3.4 | L2 | the application logs unexpected errors and security control failures such as backend TLS failures. | Cumple (verificado internamente) | Errores inesperados registrados como ERROR |
| V16.4.1 | L2 | all logging components appropriately encode data to prevent log injection. | Cumple (verificado internamente) | Saneado contra inyección (test) |
| V16.4.2 | L2 | logs are protected from unauthorized access and cannot be modified. | No cumple | Logs en `stderr` del usuario — Sin protección contra modificación (RR-05) |
| V16.4.3 | L2 | logs are securely transmitted to a logically separate system for analysis, detection, alerting, and… | No aplica | Herramienta local monousuario sin infraestructura de logs |
| V16.5.1 | L2 | a generic message is returned to the consumer when an unexpected or security-sensitive error occurs,… | Cumple (verificado internamente) | `test_internal_errors_do_not_leak_details` |
| V16.5.2 | L2 | the application continues to operate securely when external resource access fails, for example, by using… | Cumple (verificado internamente) | Fuentes caídas → `INCOMPLETE`, nunca PASS (`tests/test_resilience.py`) |
| V16.5.3 | L2 | the application fails gracefully and securely, including when an exception occurs, preventing fail-open… | Cumple (verificado internamente) | Fallo cerrado: sin manifests o con errores → `INCOMPLETE` (DG-01) |
| V16.5.4 | L3 | a "last resort" error handler is defined which will catch all unhandled exceptions. This is both to avoid… | Cumple (verificado internamente) | Manejador de último recurso en la API y en la CLI |

### V17 WebRTC

| Requisito | Nivel | Resumen oficial | Estado | Evidencia |
|---|---|---|---|---|
| V17.1.1 | L2 | the Traversal Using Relays around NAT (TURN) service only allows access to IP addresses that are not… | No aplica | No usa WebRTC. |
| V17.1.2 | L3 | the Traversal Using Relays around NAT (TURN) service is not susceptible to resource exhaustion when… | No aplica | No usa WebRTC. |
| V17.2.1 | L2 | the key for the Datagram Transport Layer Security (DTLS) certificate is managed and protected based on the… | No aplica | No usa WebRTC. |
| V17.2.2 | L2 | the media server is configured to use and support approved Datagram Transport Layer Security (DTLS) cipher… | No aplica | No usa WebRTC. |
| V17.2.3 | L2 | Secure Real-time Transport Protocol (SRTP) authentication is checked at the media server to prevent… | No aplica | No usa WebRTC. |
| V17.2.4 | L2 | the media server is able to continue processing incoming media traffic when encountering malformed Secure… | No aplica | No usa WebRTC. |
| V17.2.5 | L3 | the media server is able to continue processing incoming media traffic during a flood of Secure Real-time… | No aplica | No usa WebRTC. |
| V17.2.6 | L3 | the media server is not susceptible to the "ClientHello" Race Condition vulnerability in Datagram… | No aplica | No usa WebRTC. |
| V17.2.7 | L3 | any audio or video recording mechanisms associated with the media server are able to continue processing… | No aplica | No usa WebRTC. |
| V17.2.8 | L3 | the Datagram Transport Layer Security (DTLS) certificate is checked against the Session Description… | No aplica | No usa WebRTC. |
| V17.3.1 | L2 | the signaling server is able to continue processing legitimate incoming signaling messages during a flood… | No aplica | No usa WebRTC. |
| V17.3.2 | L2 | the signaling server is able to continue processing legitimate signaling messages when encountering… | No aplica | No usa WebRTC. |
