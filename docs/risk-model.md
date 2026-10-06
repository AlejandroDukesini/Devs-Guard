# Modelo de riesgo

DepGuard no inventa una fórmula ponderada. Usa una **tabla de decisión**
inspirada en [SSVC de CISA](https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc):
la urgencia depende de tres preguntas que se pueden comprobar.

1. **¿Se está explotando o es probable que se explote?**
   - [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog): explotación activa *confirmada*.
   - [FIRST EPSS](https://www.first.org/epss/): probabilidad estimada de explotación en los próximos 30 días.
2. **¿Cuánto daño puede hacer?** Severidad CVSS v3.x (calculada desde el vector
   que publica OSV) o, si no hay vector, la calificación cualitativa del aviso.
3. **¿Se despliega?** Dependencia de producción frente a dependencia solo de desarrollo.

## Tabla

Las reglas se evalúan de arriba abajo; gana la primera que se cumple.
`runtime` = ámbito `prod` o desconocido. Umbral EPSS por defecto: `0.10`
(configurable con `risk.epss_threshold`).

| Prioridad | Regla | Significado operativo |
|---|---|---|
| **P0** | runtime **y** (en KEV **o** (EPSS ≥ umbral **y** severidad ≥ HIGH)) | Actuar ya: explotación real o muy probable con impacto alto en algo que se despliega |
| **P1** | (runtime **y** severidad ≥ HIGH) **o** EPSS ≥ umbral **o** en KEV | Corregir en el ciclo actual |
| **P2** | (runtime **y** severidad MEDIUM o desconocida) **o** (dev **y** severidad ≥ HIGH) | Planificar |
| **P3** | resto | Mantener actualizado |

La política por defecto falla con **P1 o superior** (`policy.fail_on_priority = "P1"`)
y con cualquier hallazgo en KEV (`policy.fail_on_kev = true`).

## Principios

- **Lo desconocido nunca tranquiliza.** Un ámbito desconocido cuenta como
  runtime. Una severidad desconocida en runtime es como mínimo P2. Sin EPSS no
  hay "EPSS = 0": el motivo dice `EPSS no disponible`.
- **Directa o transitiva no cambia la prioridad.** Una vulnerabilidad
  transitiva se explota igual; lo que cambia es *cómo* se corrige. Por eso la
  ruta (`express > body-parser > qs`) aparece en el informe y en la remediación.
- **Cada hallazgo explica su prioridad.** El campo `reasons` (JSON/SARIF) y la
  sección "Por qué importan" de la tabla listan los motivos con códigos estables:

| Código | Significado |
|---|---|
| `kev` | En el catálogo CISA KEV |
| `epss_high` / `epss_low` / `epss_unknown` | EPSS por encima/debajo del umbral, o no disponible |
| `no_cve` | El aviso no tiene CVE: EPSS y KEV no aplican |
| `severity_<nivel>` | Severidad usada (con CVSS si existe) |
| `scope_prod` / `scope_dev` / `scope_unknown` | Ámbito de la dependencia |
| `direct` / `transitive` | Tipo de dependencia (con la ruta) |
| `fix_available` / `no_fix` | Existe o no versión corregida |
| `ignore_expired` | Había una excepción, pero caducó |

## Lo que el modelo no hace (todavía)

- **Alcanzabilidad (reachability):** no sabe si tu código llama a la función
  vulnerable. Una vulnerabilidad P1 puede no ser explotable en tu contexto; para
  eso existen las excepciones documentadas.
- **Entorno:** no sabe si el servicio está expuesto a Internet.
- **CVSS v4:** se reconoce pero no se puntúa (el algoritmo v4 depende de una
  tabla extensa); se usa la calificación cualitativa del aviso.

## Golden tests

La tabla está codificada en `fixtures/golden/risk.json` y la comprueban tanto
los tests de Python como los del motor JavaScript de la demo web.
