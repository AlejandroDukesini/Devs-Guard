# Arquitectura

```text
  CLI (cli.py)     Librería (dep_guard.scan)     App local (server/: FastAPI en 127.0.0.1)
        \                  |                       /        ▲ API REST + token de sesión
         ▼                 ▼                      ▼         │
                    Engine (engine.py)                   Interfaz React (web/src/local,
   ┌───────────┬────────────┬──────────────┬──────────┬────────────┐  empaquetada en el wheel)
   ▼           ▼            ▼              ▼          ▼            ▼
discovery  adapters/     sources/        correlate   risk +      patch
(archivos  18 formatos   osv (estado)    (alias,     policy      (estado de parche,
 seguros)  → Component   nvd, epss, kev  CVSS, fix)  (P0–P3,     salto mayor)
                         registries                   excepciones)
                         http (allowlist), cache
                                         ▼
                 reporters/ (table, json, sarif, cyclonedx, spdx)
```

## Flujo de un análisis

1. **Descubrimiento** (`discovery.py`): recorre la ruta sin seguir symlinks,
   descarta `node_modules`, entornos virtuales y directorios ocultos, elige el
   adaptador por nombre de archivo, aplica las sustituciones (un lockfile
   sustituye a su manifest) y avisa de los archivos reconocidos sin adaptador.
2. **Parseo** (`adapters/`): cada adaptador devuelve `Component`s con purl,
   versión exacta (o motivo de `unresolved`), ámbito, si es directa y la ruta
   más corta desde una dependencia directa. Los formatos hostiles se cargan
   con `adapters/safe_formats.py` (YAML sin alias, XML sin DTD).
3. **Fusión**: el mismo paquete@versión en varios archivos es un componente
   con varias ubicaciones.
4. **Estado** (`sources/osv.py`): `querybatch` con las versiones exactas.
   Error → `ERROR`; sin avisos → `CLEAN`; con avisos → `VULNERABLE`.
5. **Detalles**: `GET /v1/vulns/{id}` por aviso único, cacheado por `id@modified`.
6. **Correlación** (`correlate.py`): agrupa alias, calcula CVSS, elige la
   versión corregida del rango que contiene la instalada y registra de dónde
   sale la severidad.
7. **NVD** (`sources/nvd.py`, opcional): CVSS/CWE para avisos sin vector.
8. **Enriquecimiento** (`sources/enrich.py`): EPSS por CVE, catálogo KEV.
9. **Última versión** (`sources/registries.py`, opcional): registro oficial de
   cada ecosistema y consulta OSV de esa última versión.
10. **Riesgo** (`risk.py`): tabla de decisión → prioridad + motivos.
11. **Parches** (`patch.py`): estado de parche por componente.
12. **Política** (`policy.py`): excepciones y PASS/FAIL/INCOMPLETE.
13. **Informe** (`reporters/`).

## Aplicación local

`depguard serve` (extra `web`) abre un socket en `127.0.0.1`, genera un token
de sesión y sirve la interfaz compilada (`dep_guard/server/static`, generada
con `npm run build:local`). La API (`server/app.py`) ejecuta el mismo motor en
un hilo, con un análisis a la vez, y guarda un historial local con las
exportaciones ya renderizadas. Los controles de seguridad están en
`server/security.py` y se describen en [security.md](security.md) §3.

## Decisiones

| Decisión | Motivo |
|---|---|
| No reimplementar la comparación de rangos de OSV | OSV decide si una versión exacta está afectada; la comparación local solo elige la versión de corrección. |
| Un adaptador por formato, sin ejecutar gestores | Leer lockfiles como texto es reproducible y seguro; ejecutar `mvn`/`gradle`/`npm` ejecutaría código del proyecto. Lo que exige el gestor se marca `unresolved` y se recomienda un SBOM. |
| CycloneDX como vía multi-ecosistema complementaria | Los generadores oficiales resuelven árboles complejos (Maven) mejor que un parser. |
| Tabla de decisión en vez de puntuación | Una regla se puede revisar, discutir y testear. |
| Aplicación local con FastAPI como extra opcional | Interfaz sin desplegar nada ni subir código; el núcleo (CLI) mantiene solo cuatro dependencias. Antes el proyecto no tenía servidor; se añadió porque usar la UI exigía clonar el repositorio. |
| `latest` y `nvd` opcionales en la CLI | Añaden peticiones (y en NVD, un límite estricto); en CI se activan explícitamente. La app local consulta la última versión por defecto. |
| Español en la salida humana, inglés en identificadores | JSON/SARIF/códigos son estables y en inglés para integraciones. |

## Paridad con la demo web

`web/src/core/` es un port en JavaScript del motor para la demo pública del
navegador. Ambos se validan contra los mismos `fixtures/golden/`; si divergen,
falla CI. La paridad cubre el comportamiento compartido (informe, riesgo,
política, estados de parche); los formatos añadidos después (pnpm, yarn, Cargo,
Go, Composer, NuGet, Maven, Gradle, Pipfile, pyproject) solo existen en el
motor Python. Detalles en [web/README.md](../web/README.md).
