# Benchmarks: metodología

**Este repositorio no publica cifras de rendimiento ni de precisión todavía.**
Publicar números sin un procedimiento reproducible sería marketing, no ingeniería.
Esta es la metodología acordada para medirlo.

## Qué se compara

DepGuard frente a [OSV-Scanner](https://github.com/google/osv-scanner) (misma
fuente de datos, así que las diferencias reflejan parseo y correlación, no la
base de datos) y, opcionalmente, [Grype](https://github.com/anchore/grype)
(otra base de datos: útil para cobertura, no para precisión pura).

## Corpus

- 10–20 repositorios públicos con lockfiles, **fijados por commit**, que cubran:
  npm v3 con workspaces, Poetry, uv, `requirements.txt` generado por
  `pip-compile`, y un SBOM CycloneDX de un proyecto Maven.
- El corpus (URL + commit) se guarda en `benchmarks/corpus.toml`.

## Métricas

| Métrica | Cómo |
|---|---|
| Componentes detectados | Conjunto `purl@versión` de cada herramienta; diferencias revisadas a mano |
| Hallazgos | Conjunto `(id canónico, purl@versión)` tras resolver alias |
| Falsos positivos/negativos | Solo sobre las diferencias, revisando el aviso y el lockfile; se clasifican con la plantilla *accuracy* de issues |
| Tiempo | `hyperfine --warmup 1 --runs 5`, caché fría (`--no-cache`) y caliente, misma máquina y red |
| Memoria | RSS máximo (`/usr/bin/time -v`) |
| Peticiones HTTP | `depguard -v` (stats) |

## Reglas

1. Todas las herramientas se ejecutan en la misma ventana de tiempo (la base de
   datos de OSV cambia a diario).
2. Se publican las versiones exactas, los comandos, la máquina y los datos en bruto.
3. Las diferencias se explican; no se ocultan casos en los que DepGuard pierde.
