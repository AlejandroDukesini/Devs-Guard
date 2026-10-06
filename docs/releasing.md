# Proceso de release

## Preparación (una sola vez)

1. En PyPI, crea el proyecto `devs-guard` con un **Trusted Publisher**
   (Account → Publishing → Add a pending publisher): repositorio
   `AlejandroDukesini/Devs-Guard`, workflow `release.yml`, entorno `pypi`.
   No hace falta ningún token.
2. En GitHub: *Settings → Environments → New environment* `pypi`, con revisión
   obligatoria si quieres una aprobación manual antes de publicar.
3. *Settings → Code security*: activa secret scanning, push protection y
   private vulnerability reporting.

> El paquete se publica como **`devs-guard`** porque `depguard` ya pertenece a
> otro proyecto en PyPI (comprobado el 2026-10-05). El comando sigue siendo `depguard`.

## Cada release

1. Actualiza `__version__` en `dep_guard/__init__.py` (SemVer; `1.0.0b2` para betas).
2. Mueve las entradas de *Unreleased* en `CHANGELOG.md` a la nueva versión.
3. Commit, tag y push:
   ```bash
   git tag -s v1.0.0 -m "DepGuard 1.0.0"
   git push origin v1.0.0
   ```
4. `release.yml` comprueba que el tag coincide con la versión, ejecuta los
   tests, construye sdist y wheel con `SOURCE_DATE_EPOCH` (reproducibles),
   genera el SBOM y `SHA256SUMS`, firma la procedencia SLSA con Sigstore,
   publica en PyPI (con attestations PEP 740) y crea el release de GitHub.

## Verificar un release

```bash
gh attestation verify devs_guard-1.0.0-py3-none-any.whl --repo AlejandroDukesini/Devs-Guard
sha256sum -c SHA256SUMS
```
