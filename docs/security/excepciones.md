# Registro de excepciones de seguridad

Una excepción es la decisión documentada de aceptar temporalmente un hallazgo
de una herramienta del pipeline. Sin entrada en este registro no hay
excepción: el hallazgo bloquea.

## Reglas

1. Cada excepción tiene **identificador, herramienta, hallazgo, justificación
   técnica, responsable, fecha de alta y fecha de caducidad** (máximo 365
   días; `max_ignore_days` en `depguard.toml`).
2. Se aplica con el mecanismo de la propia herramienta y apunta a esta
   entrada:
   - DepGuard: `[[ignore]]` en `depguard.toml` con `reason`, `expires`, `owner`;
   - gitleaks: `.gitleaksignore` (fingerprint) con comentario `EXC-NNN`;
   - ZAP: regla `IGNORE` en el plan con comentario `EXC-NNN`.
3. Al caducar, el pipeline vuelve a fallar (DepGuard: `fail_on_expired_ignore`).
   Se renueva solo con nueva justificación.
4. Un falso positivo también se registra, para que se pueda auditar.

## Excepciones activas

| ID | Herramienta | Hallazgo | Justificación | Responsable | Alta | Caduca |
|---|---|---|---|---|---|---|
| — | — | Ninguna excepción activa a 2026-11-18 | — | — | — | — |

## Alertas revisadas que no requieren excepción

No bloquean según la política (nivel Informational) y se revisaron en la
ejecución DAST del 2026-11-18:

| Herramienta | Alerta | Revisión |
|---|---|---|
| ZAP 10027 | Information Disclosure - Suspicious Comments (bundle JS) | Comentarios de librerías minificadas (React); no contienen datos internos |
| ZAP 10109 | Modern Web Application | Informativa: la aplicación es una SPA |
| ZAP 10104 | User Agent Fuzzer | Informativa: las respuestas no cambian según el User-Agent |

## Riesgos residuales aceptados

| ID | Riesgo | Motivo de aceptación | Revisión |
|---|---|---|---|
| RR-01 | La caché local (`%LOCALAPPDATA%\depguard`, `~/.cache/depguard`) la puede modificar otro proceso del mismo usuario | Requiere acceso local como el usuario, que ya puede leer sus propios proyectos; `--no-cache` disponible | 2027-05-18 |
| RR-02 | En Windows, `--token-file` y el historial dependen de la ACL del perfil del usuario (los bits POSIX `0600` no aplican en NTFS) | La carpeta del perfil solo es accesible por el usuario y administradores | 2027-05-18 |
| RR-03 | Un hilo de análisis que supera el tiempo límite no se puede interrumpir | El servidor queda ocupado (409) hasta que termina; los timeouts HTTP acotan su duración | 2027-05-18 |
