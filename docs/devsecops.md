# Pipeline DevSecOps

Qué se ejecuta, cuándo, qué detecta cada herramienta, qué **no** detecta y
cuándo falla el pipeline. Los workflows están en `.github/workflows/`.

## Etapas

| Etapa | Workflow / job | Herramienta | Falla si |
|---|---|---|---|
| Calidad | `ci.yml` / `python` | ruff (incl. reglas `S` de seguridad), mypy `--strict`, pytest + cobertura ≥ 85 % | cualquier error, test fallido o cobertura < 85 % |
| SAST | `ci.yml` / `python` | bandit | cualquier hallazgo |
| SAST | `codeql.yml` | CodeQL `security-extended` (Python, JavaScript, Actions) | alertas en code scanning |
| Texto seguro | `ci.yml` / `python` | `scripts/check_text_safety.py` | caracteres invisibles / bidi (Trojan Source) |
| SCA (propio) | `ci.yml` / `dogfood` | DepGuard sobre sus dependencias instaladas y el repositorio | política `P1` / KEV / `INCOMPLETE` (ver `depguard.toml`) |
| SCA (segunda opinión) | `security.yml` / `sca` | OSV-Scanner sobre `web/package-lock.json` y `requirements/ci.txt` | cualquier vulnerabilidad conocida |
| SCA (npm) | `security.yml` / `sca` | `npm audit --audit-level=high` | severidad alta o crítica (incluye dev) |
| SCA (PR) | `ci.yml` / `dependency-review` | GitHub Dependency Review | dependencia nueva con severidad ≥ alta |
| Secretos | `security.yml` / `secrets` | gitleaks sobre **todo** el historial (`--redact`) | cualquier secreto |
| SBOM | `security.yml` / `sbom` | `depguard sbom` (CycloneDX 1.6 y SPDX 2.3) + validación con los esquemas oficiales | SBOM inválido según su esquema |
| DAST | `security.yml` / `dast` | OWASP ZAP 2.17 (spider, pasivo, activo) contra `depguard serve` autenticado | alerta Medium o High |
| E2E | `ci.yml` / `local-app`, `web` | Playwright contra el servidor real y la demo bajo su CSP | cualquier test fallido |
| Empaquetado | `ci.yml` / `package` | `python -m build` + comprobación de que el wheel contiene la interfaz | build fallido o interfaz ausente |
| Supply chain | `scorecard.yml`, `release.yml` | OpenSSF Scorecard; Trusted Publishing, procedencia SLSA firmada (Sigstore), SBOM y `SHA256SUMS` | — (informativo / release) |

Eventos: `push` a `Principal`, `Beta` y `main`, todos los `pull_request`,
`workflow_dispatch`, y diario (`security.yml`) porque un aviso nuevo puede
afectar a código que no cambió. Las releases se disparan con etiquetas `v*.*.*`.

## Integridad del propio pipeline

- **Acciones fijadas por SHA** (comentario con la versión); Dependabot las actualiza.
- **Herramientas como binarios con SHA-256 fijado** (gitleaks 8.30.1,
  OSV-Scanner 2.7.0, ZAP 2.17.0): no se usan acciones de terceros con
  etiquetas mutables. Se eligen versiones con al menos dos semanas de
  publicación.
- **Dependencias Python de CI y release con hashes**: `requirements/ci.txt`
  se instala con `pip install --require-hashes`; el paquete se instala con
  `--no-deps --no-build-isolation`, de modo que nada se resuelve en tiempo de
  ejecución. Regenerar tras cambiar `pyproject.toml`:

  ```bash
  uv pip compile pyproject.toml requirements/build.in --extra dev --extra web \
    --universal --python-version 3.11 --generate-hashes --no-header -o requirements/ci.txt
  ```
- **npm**: `npm ci --ignore-scripts` (sin scripts de instalación de terceros);
  `web/.npmrc` fija el registro oficial.
- **Esquemas SBOM** descargados por commit y verificados por SHA-256.
- **Permisos mínimos**: `contents: read` por defecto; `security-events: write`,
  `id-token: write` o `contents: write` solo en el job que lo necesita.
- **Sin secretos**: ningún job usa secretos; `pull_request` (no
  `pull_request_target`), así que el código de un fork nunca se ejecuta con
  privilegios; `persist-credentials: false` en cada checkout.
- **DAST sin exponer el token**: `scripts/zap_plan.py` lee el token del
  archivo que escribe `depguard serve --token-file` y genera una copia
  privada del plan; nunca aparece en la línea de comandos ni en los logs.

## Política de fallo

1. **Bloquea**: vulnerabilidad conocida con prioridad P0/P1 o en CISA KEV en
   las dependencias de DepGuard; cualquier vulnerabilidad según OSV-Scanner;
   severidad alta/crítica según `npm audit`; cualquier secreto; cualquier
   hallazgo de bandit/CodeQL; alerta DAST Medium/High; SBOM que no valida;
   análisis `INCOMPLETE` (no comprobado nunca equivale a seguro).
2. **Se informa y se revisa** (no bloquea): alertas DAST Low/Informational
   (anotación `::warning` en el run e informe adjunto), prioridades P2/P3 de
   DepGuard.
3. **Falsos positivos**: no se silencian en el workflow. Se registran como
   excepción (abajo) y se aplican con el mecanismo de la herramienta
   (`[[ignore]]` en `depguard.toml`, `.gitleaksignore`, regla de ZAP), siempre
   con caducidad. DepGuard falla si una excepción caduca
   (`fail_on_expired_ignore`).

`continue-on-error` no se usa. Los únicos `|| true` son pasos que **solo
generan un informe** de algo que otro paso ya evaluó (resumen legible del
`dogfood`, SARIF de OSV-Scanner), y están comentados.

## Excepciones

Registro, responsables, justificación y caducidad:
[security/excepciones.md](security/excepciones.md).

## Evidencias

Cada ejecución conserva sus informes como artefactos: `gitleaks-report`,
`osv-scanner-report`, `sbom`, `zap-report`, `quality-report`, `dist`, y el
SARIF de DepGuard y Scorecard en code scanning. Resultados de las ejecuciones
locales verificadas: [audit/03-informe-pruebas.md](audit/03-informe-pruebas.md).

## Herramientas evaluadas y no incorporadas

| Herramienta | Decisión | Motivo |
|---|---|---|
| Semgrep | No | CodeQL `security-extended` + bandit + ruff `S` ya cubren SAST de Python/JS/Actions; las reglas de Semgrep se descargan en tiempo de ejecución (no fijables por hash) y duplicarían hallazgos |
| Trivy | No | Su valor diferencial (imágenes de contenedor, IaC) no aplica: no hay Dockerfiles ni IaC. Para dependencias, OSV-Scanner ya aporta la segunda opinión independiente |
| pip-audit | No | Consulta la misma base (PyPA/OSV) que OSV-Scanner sobre el mismo lock; OSV-Scanner cubre además npm con un solo binario verificado |
| Dependabot | Sí (ya existía) | pip, npm y GitHub Actions semanal |
| GitHub Dependency Review | Sí (ya existía) | bloquea en PR dependencias nuevas con severidad ≥ alta |

## Qué detecta y qué no cada herramienta

| Herramienta | Detecta | No detecta |
|---|---|---|
| DepGuard / OSV-Scanner | vulnerabilidades publicadas en OSV para la versión exacta | 0-days, malware sin aviso `MAL-`, vulnerabilidades del código propio |
| npm audit | avisos de GitHub para el árbol npm | dependencias Python |
| gitleaks | patrones de secretos conocidos en el historial | secretos con formato propio no cubierto por sus reglas |
| bandit / CodeQL | patrones inseguros en el código fuente | fallos de lógica de negocio, problemas solo visibles en ejecución |
| ZAP | cabeceras, inyecciones y fallos observables por HTTP en el servidor local | rutas no alcanzables por el spider, lógica que requiere estado complejo |
| Tests adversariales | los controles de seguridad documentados (token, Host, Origin, rutas, tamaño, concurrencia) | lo que no se modeló como amenaza |
