# Configuración (`depguard.toml`)

DepGuard busca `depguard.toml` (o `.depguard.toml`) en la raíz escaneada, o
usa el archivo indicado con `--config`. Sin archivo se aplican los valores por
defecto, que son los seguros.

**Validación estricta:** una clave desconocida o un tipo incorrecto detienen
el escaneo con exit code 2. Un error tipográfico como `fail_on_kevv` no puede
debilitar en silencio una puerta de seguridad.

```toml
[scan]
exclude = ["examples/**", "fixtures/**"]   # globs relativos a la raíz

[sources]
epss = true             # consultar FIRST EPSS
kev = true              # consultar CISA KEV
timeout = 20            # segundos por petición (1–300)
retries = 3             # reintentos ante 429/5xx/red (0–10)
cache = true
private_packages = ["@acme/*", "acme-internal-*"]   # nunca se envían a OSV

[risk]
epss_threshold = 0.10   # 0–1

[policy]
fail_on_priority = "P1"        # P0 | P1 | P2 | P3 | none
fail_on_severity = "none"      # critical | high | medium | low | none
fail_on_kev = true
fail_on_incomplete = true      # exit 3 si algo no se pudo comprobar
fail_on_unresolved = false     # fallar si hay dependencias sin versión exacta
fail_on_expired_ignore = true  # una excepción caducada hace fallar
include_dev = true             # false: los hallazgos solo-dev no hacen fallar (se siguen mostrando)
max_ignore_days = 365          # límite de vigencia de una excepción

[[ignore]]
id = "CVE-2023-32681"          # coincide con cualquier alias (GHSA, PYSEC…)
package = "requests"           # opcional: nombre o purl (pkg:pypi/requests)
reason = "Solo usamos requests sin proxy; el vector no aplica"   # obligatorio, ≥ 10 caracteres
expires = 2027-01-31           # obligatorio
owner = "equipo-pagos"         # opcional
```

## Excepciones (`[[ignore]]`)

- Necesitan `id` y/o `package`. Con solo `package` se ignoran **todas** las
  vulnerabilidades de ese paquete; úsalo con cuidado.
- `reason` y `expires` son obligatorios. No existen excepciones permanentes:
  `expires` no puede superar `max_ignore_days` desde hoy.
- Al caducar, la excepción **deja de aplicarse** y, por defecto, el escaneo
  falla con un mensaje que la identifica.
- Una excepción que no coincide con nada genera un aviso (`unused_ignore`) para
  que se pueda limpiar.
- Los hallazgos ignorados **no desaparecen**: se muestran en la tabla, en JSON
  (`status: "ignored"`), en SARIF como *suppression* aceptada y en CycloneDX
  como análisis VEX con el motivo.

## Paquetes privados

`private_packages` (patrones `fnmatch` sobre el nombre) evita enviar a OSV.dev
los nombres de paquetes internos. Esas dependencias aparecen con estado
`private`: **no se comprueban**, y el informe lo dice.

## Opciones de la CLI que sobrescriben la configuración

| Opción | Efecto |
|---|---|
| `--fail-on P0..P3/none` | Sustituye `policy.fail_on_priority` |
| `--allow-incomplete` | Equivale a `fail_on_incomplete = false` |
| `--no-epss` / `--no-kev` | Desactiva el enriquecimiento |
| `--offline` | Solo caché local; lo no cacheado queda como error (exit 3) |
| `--no-cache` | No lee ni escribe la caché |
