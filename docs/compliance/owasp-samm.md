# OWASP SAMM 2 — autoevaluación de madurez

Autoevaluación a 2026-11-18. Escala SAMM: 0 (práctica no realizada) a 3
(práctica completa y medida). Se puntúa de forma conservadora: un nivel solo
cuenta si hay evidencia en el repositorio. Un proyecto de un solo mantenedor
no alcanza los niveles altos de las prácticas organizativas, y eso se refleja
aquí en lugar de ocultarse.

| Función | Práctica | Nivel | Evidencia | Siguiente paso para subir de nivel |
|---|---|---|---|---|
| Gobierno | Estrategia y métricas | 1 | Objetivos de seguridad en `SECURITY.md` y `docs/devsecops.md` | Definir métricas (tiempo de corrección, % de hallazgos con excepción) y revisarlas por release |
| Gobierno | Política y cumplimiento | 2 | Políticas de fallo y excepciones, evaluaciones ASVS/SSDF/ISO trazables | Verificación periódica (trimestral) del cumplimiento con las mismas matrices |
| Gobierno | Educación y orientación | 1 | `CONTRIBUTING.md`, `docs/security.md` | Guía de codificación segura para contribuidores con ejemplos del proyecto |
| Diseño | Evaluación de amenazas | 2 | Modelos de amenazas por componente (`docs/security.md` §1-3), riesgos residuales registrados | Revisar el modelo en cada cambio de arquitectura y contrastarlo con un tercero |
| Diseño | Requisitos de seguridad | 2 | ASVS 5.0 L2 como requisitos de la app local, requisitos de proveedores (fuentes allowlist) | Requisitos de seguridad explícitos en las plantillas de issues/PR |
| Diseño | Arquitectura de seguridad | 2 | Patrones aplicados de forma sistemática: fallo cerrado, loopback+token, parsers sin ejecución, allowlists | Componentes reutilizables documentados como patrón (p. ej. `PathGuard`) |
| Implementación | Construcción segura | 3 | Builds reproducibles, dependencias con hashes, herramientas con SHA-256, SBOM, procedencia SLSA firmada, comprobación del contenido del wheel | Mantener |
| Implementación | Despliegue seguro | 2 | Trusted Publishing (sin tokens), atestaciones, entornos protegidos en `release.yml` | Verificación automática de la atestación tras publicar |
| Implementación | Gestión de defectos | 2 | Registro de vulnerabilidades con causa raíz y regresión; excepciones con caducidad; SARIF en code scanning | Métricas de defectos por release |
| Verificación | Evaluación de arquitectura | 1 | Auditoría interna y evaluación ASVS | Revisión de arquitectura independiente |
| Verificación | Pruebas guiadas por requisitos | 2 | Tests de seguridad mapeados a cada control y a requisitos ASVS (`tests/test_server.py`, `tests/test_security.py`, `tests/test_adversarial.py`) | Trazabilidad automática requisito→test |
| Verificación | Pruebas de seguridad | 2 | SAST (CodeQL, bandit), SCA (DepGuard, OSV-Scanner, npm audit), secretos (gitleaks), DAST autenticado (ZAP), e2e | Prueba de penetración manual independiente; fuzzing de parsers |
| Operaciones | Gestión de incidentes | 1 | Canal privado de notificación y plazos (`SECURITY.md`) | Procedimiento de respuesta documentado y ensayado |
| Operaciones | Gestión del entorno | 2 | Dependabot, escaneo diario, actualización de dependencias vulnerables (DG-05) | Inventario de configuración de los entornos de CI |
| Operaciones | Gestión operativa | 1 | Clasificación de datos y retención del historial (`docs/security.md` §4) | Procedimientos de copia y retirada de datos para la app local |

Media: **1,7 / 3** (26 puntos en 15 prácticas). Las prácticas más maduras son las técnicas (construcción
segura, pruebas de seguridad, arquitectura). Las de menor nivel dependen de
procesos organizativos (formación, incidentes, evaluación independiente).
