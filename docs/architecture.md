# Arquitectura

```text
           CLI (dep_guard/cli.py)        Librería (dep_guard.scan)
                         \                 /
                          ▼               ▼
                   Engine (dep_guard/engine.py)
   ┌──────────────┬──────────────┬──────────────┬─────────────┐
   ▼              ▼              ▼              ▼             ▼
discovery     adapters/       sources/       correlate     risk + policy
(archivos     (lockfiles,     osv (estado)   (alias,       (tabla P0–P3,
 seguros)      SBOM → purl)   epss, kev      CVSS, fix)     excepciones)
                              http, cache
                                         ▼
                                 reporters/ (table, json, sarif, cyclonedx)
```

## Flujo de un escaneo

1. **Descubrimiento** (`discovery.py`): recorre la ruta sin seguir symlinks,
   descarta `node_modules`, entornos virtuales y directorios ocultos, y elige el
   adaptador por nombre de archivo. Un lockfile sustituye al `package.json` vecino.
2. **Parseo** (`adapters/`): cada adaptador devuelve `Component`s con purl,
   versión exacta (o motivo de `unresolved`), ámbito prod/dev, si es directa y
   la ruta más corta desde una dependencia directa (BFS sobre el grafo del lockfile).
3. **Fusión**: el mismo paquete@versión declarado en varios archivos es un
   solo componente con varias ubicaciones.
4. **Estado** (`sources/osv.py`): `querybatch` con las versiones exactas.
   Error → `ERROR`; sin avisos → `CLEAN`; con avisos → `VULNERABLE`.
5. **Detalles**: un `GET /v1/vulns/{id}` por aviso único, cacheado por `id@modified`.
6. **Correlación** (`correlate.py`): agrupa alias en un hallazgo, calcula
   CVSS, toma la versión corregida del rango que contiene la versión instalada.
7. **Enriquecimiento** (`sources/enrich.py`): EPSS por CVE, catálogo KEV.
8. **Riesgo** (`risk.py`): tabla de decisión → prioridad + motivos.
9. **Política** (`policy.py`): aplica excepciones y decide PASS/FAIL/INCOMPLETE.
10. **Informe** (`reporters/`).

## Decisiones

| Decisión | Motivo |
|---|---|
| No reimplementar la comparación de rangos de OSV | OSV ya decide si una versión exacta está afectada; reimplementarlo para 10 ecosistemas añadiría errores. La comparación local solo elige la versión de corrección. |
| CycloneDX como vía multi-ecosistema | Los generadores oficiales resuelven mejor sus árboles que un parser propio. |
| Tabla de decisión en vez de puntuación | Una puntuación 0–10 es opaca; una regla se puede revisar, discutir y testear. |
| Sin servidor, API ni base de datos | Una CLI y una librería cubren los casos de uso (local, CI, PR); un servicio añadiría superficie de ataque y mantenimiento sin valor proporcional. |
| Español en la salida humana, inglés en identificadores | La salida para personas sigue el idioma del proyecto; JSON/SARIF/códigos son estables y en inglés para integraciones. |

## Paridad con la demo web

`web/src/core/` es un port en JavaScript del motor. Ambos se validan contra los
mismos archivos de `fixtures/golden/`; si divergen, falla CI.
