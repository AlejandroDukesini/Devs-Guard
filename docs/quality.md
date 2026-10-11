# Centro de seguridad y calidad y certificado

La web incluye un conjunto de pruebas que se **ejecuta de verdad** sobre el motor
que usa la propia página (`web/src/core`). La misma suite corre en el navegador
y en CI con vitest, así que el resultado de la web y el de CI salen del mismo
código.

```text
código evaluado ──► suite (web/src/quality/registry.js) ──► resultados + evidencias
   (huella SHA-256)          navegador o vitest                       │
                                                                       ▼
                        certificado ◄── informe sellado (SHA-256) ◄── historial verificado
```

## Cómo ejecutarla

| Dónde | Cómo | Resultado |
|---|---|---|
| Web | Sección «Centro de seguridad y calidad» → **Ejecutar pruebas de seguridad** | Panel, historial (este navegador) y certificado |
| Local / CI | `cd web && npm run quality` | `web/reports/quality-report.json` (artefacto `quality-report` en CI) |
| Tests de la suite | `npm test` (incluye `tests/quality.test.jsx`) | Falla si alguna prueba falla o da error |
| E2E | `npm run test:e2e` (`e2e/quality.spec.js`) | Ejecuta la suite en Chromium bajo la CSP de producción y compara web, certificado e informe |

El botón no ejecuta comandos: carga el módulo de pruebas (`execute.js`) y lo
ejecuta en la pestaña. No hay backend. Solo se puede hacer una ejecución a la
vez: hay un bloqueo en la página y otro entre pestañas (`navigator.locks`).

## Qué se prueba (46 pruebas)

| Categoría | Ejemplos |
|---|---|
| Unitarias | Comparación de versiones, CVSS, tabla P0–P3, PEP 508, limpieza de caracteres, validación de configuración |
| Integración | Los 8 informes completos deben ser idénticos a los golden generados por Python |
| Funcionales | Instantánea sin red, paquetes privados nunca enviados, excepciones, CycloneDX reutilizable, avisos renderizados como texto (DOM), cabeceras de seguridad servidas |
| Negativas | Caída de OSV → INCOMPLETE, lockfile corrupto, path traversal, límites de tamaño, hosts no permitidos, `__proto__` en lockfiles |
| Regresión | Errores ya corregidos, veredictos de las muestras de la demo, coherencia de `netlify.toml` |
| Rendimiento | Escaneo real dentro de presupuesto (`PERF_BUDGET`), comparaciones a escala, descubrimiento |
| Integridad y persistencia | Informe determinista, caché grabada y reproducida, historial a prueba de manipulación, huellas SARIF |
| Dependencias | Procedencia del lockfile (registro oficial + sha512), scripts de instalación desactivados, dependencias mínimas, **OSV en vivo** sobre `web/package-lock.json` |

Cada resultado registra: id, nombre, descripción, categoría, severidad, estado
(`passed`, `failed`, `skipped`, `error`), inicio, duración, evidencia y, si falla,
la recomendación. Una prueba que termina sin evidencia cuenta como `error`. Las
evidencias se limpian: se eliminan los caracteres de control y las rutas locales.

Dos pruebas dependen del entorno y se marcan `skipped` (nunca `passed`) cuando no
se pueden ejecutar:

- **DEP-004**: necesita red para consultar OSV.dev.
- **FUN-006**: necesita la build de producción servida (`vite preview` o Netlify).

## Fórmulas

- **Aprobación** = aprobadas / (aprobadas + fallidas + con error) × 100. Solo cuenta las pruebas ejecutadas.
- **Ejecutado** = (aprobadas + fallidas + con error) / total × 100. Las pruebas omitidas lo reducen.

## Certificado

| Estado | Cuándo |
|---|---|
| No evaluado | No hay ejecución |
| No aprobado | Hay alguna prueba fallida, crítica o no |
| Evidencia insuficiente | Hay omitidas, errores de ejecución, una suite incompleta o una versión desconocida |
| Corresponde a una versión anterior | Todo pasó, pero el código servido ya no es el evaluado |
| Pruebas internas superadas | Las 46 pruebas se ejecutaron y pasaron sobre esta misma build |

- **Identificador**: `DG-QC-` seguido de los 16 primeros hexadecimales del SHA-256 del informe.
- **SHA-256 del informe**: se calcula sobre el JSON canónico (claves ordenadas) de todo
  el informe excepto el propio campo `sha256`. Al cargar el historial se recalcula,
  y una entrada manipulada se descarta. «Verificar un informe» hace la misma
  comprobación con un archivo descargado. Esta huella demuestra que el informe no
  se ha modificado; **no mide la seguridad del código**.
- **Huella del código evaluado** (`web/build-info.js`): es el SHA-256 de los archivos de
  `web/src`, `fixtures/`, `web/package*.json`, `web/security-headers.js`,
  `web/index.html` y `netlify.toml`, con los finales de línea normalizados. Se
  inyecta en la build; si no coincide con la de la ejecución, el certificado
  queda como «versión anterior». También se guarda el commit y si había cambios
  sin commit.
- **Imprimir / PDF** usa el diálogo de impresión del navegador y solo imprime el certificado.

## Limitaciones

- Son pruebas internas automatizadas. **No** son una auditoría independiente ni una
  certificación acreditada.
- El motor Python solo se cubre aquí a través de los golden compartidos; su suite
  completa (pytest, ruff, mypy, bandit) corre en CI.
- El historial vive en el `localStorage` de cada navegador (10 ejecuciones como
  máximo) y no se comparte entre dispositivos.
- En `npm run dev`, la huella del código se calcula al arrancar el servidor; tras
  editar archivos, reinicia el servidor para que la detección de versión sea exacta.
- Los presupuestos de rendimiento son amplios a propósito: detectan regresiones
  graves, no diferencias entre equipos.
