# Registro de vulnerabilidades y defectos

Cada entrada: evidencia, ubicación, impacto, condiciones de explotación,
severidad, corrección, prueba de regresión y resultado de la nueva evaluación.
Incluye los defectos de la auditoría inicial (DG-xx) y los encontrados durante
el desarrollo y las pruebas (DV-xx). Fecha: 2026-11-18. Rama `Beta`.

## Vulnerabilidades confirmadas

### DG-01 — Un análisis sin manifiestos devolvía PASS (fallo abierto)
- **Severidad**: HIGH. **Tipo**: falso negativo con veredicto tranquilizador.
- **Evidencia**: carpeta con solo `pyproject.toml` que fija `requests==2.19.0`
  → `Política: PASS`, exit 0, "No se encontraron vulnerabilidades conocidas".
- **Ubicación**: `dep_guard/policy.py` (`evaluate`), `web/src/core/policy.js`.
- **Impacto**: en CI, un repositorio cuyo ecosistema no se reconocía pasaba la
  puerta de seguridad.
- **Explotación**: basta con un proyecto en un formato no soportado; sin
  privilegios.
- **Corrección**: `manifest_count == 0` → `INCOMPLETE` (exit 3) en ambos
  motores; además los archivos reconocidos sin adaptador también producen
  `INCOMPLETE` (DG-03). Commit `428c00a`.
- **Regresión**: `test_directory_without_manifests_is_incomplete_not_pass`,
  `nothing analysed is never PASS (DG-01)` (vitest),
  `test_recognised_but_unsupported_files_make_the_scan_incomplete`.
- **Nueva evaluación**: la reproducción devuelve `INCOMPLETE`, exit 3. Cerrada.

### DG-04 — Anidamiento hostil abortaba el análisis completo
- **Severidad**: MEDIUM (denegación de servicio; falla cerrado).
- **Evidencia**: `package-lock.json` con 100 000 niveles de corchetes →
  `internal error: RecursionError`, exit 2.
- **Ubicación**: `dep_guard/engine.py` (`parse_files`), `dep_guard/config.py`.
- **Impacto**: un archivo hostil en un monorepo impedía analizar el resto; en
  la app local habría sido un 500 por petición.
- **Explotación**: incluir el archivo en el repositorio analizado.
- **Corrección**: `RecursionError` invalida solo ese archivo
  ("nesting too deep to parse safely"); en la configuración es `ConfigError`.
  Commit `428c00a`.
- **Regresión**: `test_hostile_nesting_invalidates_one_file_not_the_scan`,
  `test_hostile_nesting_in_config_is_a_config_error`.
- **Nueva evaluación**: el resto de manifests se analiza; veredicto
  `INCOMPLETE`. Cerrada.

### DG-05 — Dependencias de desarrollo web con avisos publicados
- **Severidad**: HIGH (herramientas de desarrollo; no forman parte del sitio
  publicado).
- **Evidencia**: `npm audit` y el autoescaneo de DepGuard: vite 8.3.2
  (launch-editor: ejecución de comandos en Windows, lectura fuera de la raíz
  del servidor de desarrollo), undici 8.11.2 (8 avisos), zod 4.6.5,
  minimatch 10.2.6, picomatch/tinyglobby/fdir (ReDoS).
- **Ubicación**: `web/package-lock.json`.
- **Impacto**: compromiso del equipo del desarrollador al usar el dev server.
- **Explotación**: requiere que el desarrollador abra una página maliciosa
  mientras el dev server está activo, o entradas hostiles a las librerías.
- **Corrección**: `npm audit fix --ignore-scripts` (solo parches y menores):
  vite 8.3.8, undici 8.12.4, zod 4.6.7, minimatch 11.0.9, eslint 10.15.0.
  Commit `428c00a`.
- **Regresión**: `npm audit --audit-level=high` y OSV-Scanner en
  `security.yml`; autoescaneo diario.
- **Nueva evaluación**: `npm audit` → 0 vulnerabilidades; OSV-Scanner → "No
  issues found" sobre 281 paquetes. Cerrada.

### DV-01 — El bloqueo de "un análisis a la vez" se liberaba antes de tiempo
- **Severidad**: MEDIUM (denegación de servicio local).
- **Evidencia**: si el bucle de eventos cancelaba la espera (cierre,
  desconexión), el *callback* del futuro liberaba el bloqueo mientras el hilo
  seguía analizando; se podían acumular análisis concurrentes.
- **Ubicación**: `dep_guard/server/app.py` (`run_scan`).
- **Corrección**: el propio hilo de trabajo libera el bloqueo en `finally`.
  Commit `728c794`.
- **Regresión**: `test_slow_scans_time_out_and_keep_the_lock_until_they_end`.
- **Nueva evaluación**: tras el 504 el servidor sigue ocupado hasta que el
  hilo termina. Cerrada.

### DV-02 — La sesión no caducaba si el reloj empezaba en 0
- **Severidad**: LOW (inalcanzable con el reloj monotónico real, patrón
  incorrecto).
- **Evidencia**: `now - (settings.started or now)` trata el instante `0.0`
  como "sin fijar".
- **Ubicación**: `dep_guard/server/app.py` (middleware).
- **Corrección**: comprobación explícita de `None`. Commit `3747457`.
- **Regresión**: `test_session_has_an_absolute_lifetime`.
- **Nueva evaluación**: la caducidad absoluta se aplica. Cerrada.

## Defectos funcionales con impacto en la seguridad del resultado

### DG-02 / DG-03 — Ecosistemas y manifests ignorados en silencio
- **Severidad**: HIGH (DG-02) / MEDIUM (DG-03).
- **Evidencia**: `pyproject.toml` (PEP 621), pnpm, yarn, Pipfile.lock, Cargo,
  Go, Composer, NuGet, Maven y Gradle no se analizaban ni se avisaba.
- **Corrección**: un adaptador por formato; archivos reconocidos sin adaptador
  → aviso + `INCOMPLETE`. Commit `32859c7`.
- **Regresión**: `tests/test_ecosystems.py` (inventarios exactos por formato).
- **Nueva evaluación**: comparación con OSV-Scanner sobre lockfiles reales:
  19/19 avisos (pnpm) y 7/7 (Cargo), inventarios 281/281 y 50/50. Cerrada.

### DV-03 — Nombre de paquete mal extraído en Yarn Berry
- **Severidad**: MEDIUM (falso negativo: el paquete se consultaba con un
  nombre inexistente).
- **Evidencia**: `typescript@patch:typescript@^5.0.0#…` producía el nombre
  `typescript@patch:typescript`.
- **Corrección**: el nombre termina en la primera `@` tras la posición 0.
  Commit `32859c7`.
- **Regresión**: fixture `yarn-berry` en `test_ecosystems.py`.
- **Nueva evaluación**: nombre `typescript`. Cerrada.

### DV-04 — Una versión inexistente se clasificaba como "actualizada"
- **Severidad**: MEDIUM (conclusión tranquilizadora falsa).
- **Evidencia**: `requests==99.0.0` con `--latest` → `up_to_date` por ser
  mayor que la última estable.
- **Corrección**: versión posterior a la última estable → "pre-release o no
  publicada", nunca `up_to_date` (ambos motores). Commit `c722e9c`.
- **Regresión**: `test_every_patch_state_with_its_reason`,
  `test_nonexistent_version_is_never_reported_clean_offline`.
- **Nueva evaluación**: estado `no_known_vulnerabilities` con la explicación.
  Cerrada.

### DV-05 — El wheel no incluía la interfaz web
- **Severidad**: MEDIUM (funcionalidad publicada rota).
- **Evidencia**: `python -m build` genera el wheel desde el sdist, y el sdist
  excluía `dep_guard/server/static/` (ignorado por git): 0 archivos de la
  interfaz en el wheel.
- **Corrección**: `artifacts` en `[tool.hatch.build]` (ambos objetivos);
  comprobación del contenido del wheel en `ci.yml` y `release.yml`.
  Commit `1223de0`.
- **Nueva evaluación**: wheel instalado en un entorno limpio sirve la
  interfaz desde `site-packages`. Cerrada.

### DV-06 — CycloneDX atribuía a OSV puntuaciones que venían de NVD
- **Severidad**: LOW (integridad de la trazabilidad).
- **Corrección**: fuente `NVD` y método `CVSSv4` cuando corresponde.
  Commit `91cd069`.
- **Nueva evaluación**: validado contra el esquema oficial CycloneDX 1.6.
  Cerrada.

### DV-07 — Paquete ausente del registro público mostrado como "no consultado"
- **Severidad**: LOW (se perdía una señal de *dependency confusion*).
- **Corrección**: la nota del registro llega al estado de parche ("no existe
  en el registro público"). Commit `728c794`.
- **Regresión**: `test_scan_with_latest_distinguishes_every_state`.
- **Nueva evaluación**: visible en la UI y el JSON. Cerrada.

## Brechas de requisitos (ASVS 5.0) corregidas

Commit `3747457`: caducidad de sesión por inactividad y absoluta (V7.3),
cierre de sesión que revoca el token y limpia el almacenamiento (V7.4.1,
V7.4.4, V14.3.1), registro de eventos de seguridad sin secretos y saneado
(V16.2, V16.3, V16.4.1), `charset` en JSON y formato de error único (V4.1.1),
validación sin coerción de tipos (V15.3.5), prueba de *prototype pollution*
(V15.3.6). Pruebas en `tests/test_server.py` y `web/tests/core.test.js`.

## Hallazgos de infraestructura de pruebas

- **DAST sin autenticación efectiva**: ZAP 2.17 no expande variables de
  entorno en valores de cabecera (comprobado capturando la cabecera
  `Authorization: Bearer ${DEPG…}` con un servidor de eco). Las dos primeras
  ejecuciones solo atacaron la barrera de autenticación. Corregido con
  `scripts/zap_plan.py`; la ejecución válida es la tercera.
- **Pruebas que tocaban el historial real del usuario**: el e2e de la app
  local usaba la caché por defecto; ahora `DEPGUARD_CACHE_DIR` aislado. La
  entrada creada durante la prueba manual se eliminó tras comprobar que era
  propia.

## Riesgos residuales

Ver [../security/excepciones.md](../security/excepciones.md) (RR-01 a RR-06).
