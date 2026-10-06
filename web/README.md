# DepGuard: demo web

Demo pública de [DepGuard](../README.md) que se ejecuta **entera en el navegador**:
no hay backend, base de datos ni secretos. Es un sitio estático (React + Vite +
Tailwind) desplegado en Netlify.

## Qué es real y qué no

| | |
|---|---|
| Motor de escaneo | **Real.** `src/core/` es un port en JavaScript del motor de Python (`dep_guard/`): mismos adaptadores, correlación, CVSS, modelo de riesgo, política y formato de informe. |
| Paridad con la CLI | **Verificada.** `tests/parity.test.js` ejecuta los mismos casos golden que pytest (`../fixtures/golden/`). Además, se comprobó a mano con datos reales: la CLI y la demo producen informes idénticos para los ejemplos. |
| Datos de vulnerabilidades | **Reales.** Modo *En vivo*: OSV.dev y FIRST EPSS por CORS, CISA KEV a través de un rewrite de Netlify. Modo *Instantánea*: respuestas reales grabadas con `npm run snapshot` (la fecha aparece en la interfaz). |
| Proyectos de ejemplo | **Reales.** Paquetes y versiones reales; el `package-lock.json` lo generó npm (`--package-lock-only --ignore-scripts`). |
| "Simular caída de OSV" | **Simulación declarada.** Fuerza respuestas 503 para mostrar que el resultado es `INCOMPLETE` y nunca un falso `PASS`. |

¿Por qué un port y no el Python original con Pyodide? Por el tiempo de carga
(Pyodide descarga unos 10 MB y tarda varios segundos en arrancar). El coste de
tener dos implementaciones se controla con los golden compartidos: si divergen,
falla el CI.

## Arquitectura

```text
Navegador
  ├─ React UI (src/components)           File API: los archivos no se suben a ningún sitio
  └─ Motor (src/core)
       ├─ adapters/   lockfiles y SBOM → componentes (purl, versión, ruta, prod/dev)
       ├─ sources/    OSV querybatch + detalles, EPSS, KEV  ─── fetch ──┐
       ├─ correlate · risk · policy                                    │
       └─ reporters/  report v1 (JSON), SARIF, CycloneDX               │
                                                                       ▼
          https://api.osv.dev   https://api.first.org   /api/kev → (Netlify rewrite) → cisa.gov
```

## Ejecutar en local

```bash
cd web
npm ci --ignore-scripts
npm run dev          # http://localhost:5173 (con proxy /api/kev igual que Netlify)
```

| Comando | Qué hace |
|---|---|
| `npm test` | Tests unitarios, de seguridad y de paridad con Python (vitest) |
| `npm run test:e2e` | Playwright en escritorio y móvil, **sin red externa** y bajo la CSP de producción |
| `npm run lint` | ESLint (prohíbe `dangerouslySetInnerHTML`, `innerHTML`, `eval`) |
| `npm run build` | Build de producción en `dist/` |
| `npm run snapshot` | Regraba la instantánea con datos reales (necesita internet) |

No hay variables de entorno: nada que configurar ni ningún secreto que filtrar.

## Desplegar en Netlify

1. En Netlify: *Add new site → Import an existing project* → repositorio
   `AlejandroDukesini/Devs-Guard`, rama `Beta` (o la que se publique).
2. Netlify lee `../netlify.toml`: base `web`, comando `npm run build`, publica
   `dist`, Node 24, `--ignore-scripts`, rewrite de KEV y cabeceras de seguridad.
3. No hace falta configurar nada más. El plan gratuito es suficiente: es un
   sitio estático de unos 110 KB gzip iniciales.

Coste estimado: **0 €** (hosting estático gratuito; las APIs de OSV, FIRST y CISA son públicas).

## Seguridad

- **CSP estricta** (`security-headers.js`, replicada en `netlify.toml` y comprobada por un test):
  sin scripts inline, `connect-src` limitado a OSV y FIRST, sin iframes, sin formularios externos.
- El texto de los avisos se renderiza como texto (React), nunca como HTML; los
  enlaces solo pueden ser `https:` y llevan `rel="noopener noreferrer nofollow"`.
- Saneado de caracteres de control, bidi y de ancho cero en todo dato externo.
- Límites: 2 MB por archivo, 8 MB en total, 200 archivos; filtrado por nombre antes de leer.
- Cliente HTTP con allowlist de hosts, sin redirecciones, límite de tamaño y reintentos.
- Privacidad: solo el ecosistema, el nombre y la versión de cada paquete salen del
  navegador (hacia OSV.dev), y los CVE hacia FIRST. El modo *Instantánea* no hace
  ninguna petición externa (lo verifican los tests e2e bloqueando la red).

## Limitaciones de la demo

- Sin caché persistente ni modo offline general: la instantánea solo cubre los ejemplos.
- Sin `private_packages` útil en la práctica: si tus paquetes son privados, usa la CLI.
- Si OSV.dev o FIRST cambian su política de CORS, el modo en vivo dejaría de
  funcionar (el resultado sería `INCOMPLETE`, nunca un falso PASS) y quedaría la instantánea.
- Las [limitaciones del motor](../docs/limitations.md) aplican igual.
