# Informe de conformidad

Fecha: 2026-11-18. Versión evaluada: rama `Beta` (1.0.0b2 + cambios no
publicados). Evaluador: el propio proyecto (evaluación **interna**).

## 1. Declaración

DepGuard **no tiene ninguna certificación**. Este informe resume una
evaluación interna frente a estándares reconocidos, con evidencia
reproducible en el repositorio. No sustituye una auditoría independiente ni
debe presentarse como certificación, acreditación o garantía de ausencia de
vulnerabilidades.

## 2. Resultado por estándar

| Estándar | Alcance | Resultado interno | Detalle |
|---|---|---|---|
| OWASP ASVS 5.0 (objetivo L2) | App local `depguard serve` | 107 de 114 requisitos L1+L2 aplicables cumplidos; 6 parciales; 1 no cumplido (V16.4.2, protección de logs) | [asvs-5.0.md](asvs-5.0.md) |
| NIST SSDF SP 800-218 | Proceso de desarrollo | 14 de 19 prácticas cumplidas; 4 parciales; 1 pendiente de verificar en GitHub | [nist-ssdf.md](nist-ssdf.md) |
| OWASP SAMM 2 | Proceso de desarrollo | Madurez media 1,7 / 3 | [owasp-samm.md](owasp-samm.md) |
| ISO/IEC 27001:2022 | Controles del Anexo A que el proyecto apoya | No certificable como producto; apoya 8.8, 8.25–8.29, 5.21 y otros | [iso-27001.md](iso-27001.md) |
| Cadena de suministro | Dependencias, build y releases | Lock con hashes, herramientas con SHA-256, SBOM CycloneDX/SPDX validados, procedencia SLSA firmada, Trusted Publishing | [../devsecops.md](../devsecops.md) |

## 3. Clasificación del cumplimiento

| Categoría | Contenido |
|---|---|
| Cumplimiento comprobado internamente | Requisitos con test, configuración o revisión citada (ASVS «Cumple», SSDF «Cumple») |
| Cumplimiento parcial | ASVS V4.2.1, V6.3.3, V12.3.1, V13.3.1, V14.2.1, V16.3.1 (L2) y 8 requisitos L3; SSDF PO.2, PO.5, PW.2, PW.7 |
| No cumplimiento | ASVS V16.4.2 (L2) y V3.4.7, V3.7.5 (L3) |
| No aplica | 191 requisitos ASVS (OAuth, WebRTC, contraseñas, cookies, TLS de servidor…), justificados uno a uno o por sección |
| No evaluado | Ninguno dentro del alcance |
| Pendiente de evaluación independiente | Todo lo anterior; en particular: prueba de penetración, revisión de diseño, configuración de GitHub (PS.1), ejecución de los workflows en GitHub Actions |

## 4. Requisitos pendientes de validación independiente

1. **Prueba de penetración** de `depguard serve` y de los parsers frente a
   archivos hostiles, por un tercero cualificado, usando ASVS 5.0 L2 y la
   OWASP Web Security Testing Guide como referencia.
2. **Revisión de diseño y de código** por una persona distinta del
   mantenedor (SSDF PW.2 y PW.7).
3. **Configuración del repositorio** (protección de ramas, revisiones
   obligatorias, 2FA, informe privado de vulnerabilidades, Trusted Publisher
   de PyPI).
4. **Primera ejecución** de `ci.yml`, `security.yml` y `release.yml` en
   GitHub Actions, con sus artefactos como evidencia.

## 5. Evaluaciones externas recomendadas

Programas reales y aplicables a este tipo de proyecto, sin afirmar ninguna
acreditación concreta de un proveedor:

| Evaluación | Qué aporta | Quién la realiza |
|---|---|---|
| Prueba de penetración / verificación ASVS L2 | Evidencia independiente de los controles de la app local | Empresa o profesional de seguridad independiente con experiencia en aplicaciones web |
| OpenSSF Best Practices Badge | Autoevaluación pública y verificable frente a criterios de la OpenSSF (no es una auditoría) | El propio proyecto, en bestpractices.dev |
| OpenSSF Scorecard | Puntuación automatizada de prácticas del repositorio (ya configurada en `scorecard.yml`) | Automatizada |
| Verificación de nivel SLSA | Confirmar el nivel de la procedencia de build generada con las atestaciones de GitHub | Revisión interna o de terceros frente a la especificación SLSA v1 |
| ISO/IEC 27001 | Solo para una organización que mantenga un SGSI que incluya el desarrollo de DepGuard | Organismo de certificación acreditado por el organismo nacional de acreditación correspondiente (miembro del IAF) |

## 6. Uso correcto de estas afirmaciones

Se puede decir: «evaluado internamente frente a OWASP ASVS 5.0 nivel 2, con
la matriz y las evidencias publicadas en el repositorio».

No se debe decir: «certificado», «conforme a ISO 27001», «100 % seguro» o
«libre de vulnerabilidades».
