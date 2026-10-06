# Integración CI/CD

## Exit codes

| Código | Veredicto | Significado |
|---|---|---|
| `0` | PASS | Política cumplida y todas las dependencias comprobadas |
| `1` | FAIL | Política incumplida (gana sobre INCOMPLETE) |
| `2` | — | Error de la herramienta: argumentos, ruta, configuración inválida, fallo interno |
| `3` | INCOMPLETE | Sin violaciones, pero algo no se pudo comprobar (red, OSV, manifest corrupto) |

Si prefieres no bloquear por caídas de terceros: `--allow-incomplete`
(el informe sigue indicando qué no se comprobó).

## GitHub Actions

Con la action incluida en este repositorio (instala DepGuard desde su código):

```yaml
name: Dependencies
on: [push, pull_request]
permissions:
  contents: read
jobs:
  depguard:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v7
      - id: depguard
        uses: AlejandroDukesini/Devs-Guard@v1   # fija un SHA en producción
        with:
          path: .
          fail-on: P1
      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: depguard.sarif
          category: depguard
```

Los hallazgos aparecen en *Security → Code scanning* con su prioridad, y el
resumen legible en el *job summary*.

## GitLab CI

```yaml
depguard:
  image: python:3.13-slim
  script:
    - pip install devs-guard
    - depguard scan . --format json --output depguard.json
  artifacts:
    when: always
    paths: [depguard.json]
```

## Jenkins

```groovy
stage('Dependencies') {
  steps {
    sh 'pip install devs-guard'
    sh 'depguard scan . --format sarif --output depguard.sarif'
  }
  post { always { archiveArtifacts artifacts: 'depguard.sarif' } }
}
```

## Pre-commit / local

```bash
depguard scan . -q          # una línea con el veredicto
depguard scan . -v          # tiempos y peticiones en stderr
```

## Rendimiento en CI

- Una sola petición `querybatch` por cada 1000 dependencias.
- Los detalles de cada aviso se cachean por `id@modified`: en la segunda
  ejecución solo se descargan los avisos nuevos o modificados. Persiste el
  directorio de caché entre ejecuciones (`depguard cache path`; o fija
  `DEPGUARD_CACHE_DIR`) con la caché de tu CI para aprovecharlo.
- EPSS y KEV se cachean 24 h (se publican a diario).
