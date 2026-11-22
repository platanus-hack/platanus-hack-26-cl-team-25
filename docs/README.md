# Documentación de Immune

Índice de la documentación. Cada documento es de un solo tipo: tutorial, guía de tareas, referencia o explicación.
Cada dato tiene una única fuente; los demás documentos enlazan a ella.

## En este directorio

| Documento | Tipo | Contenido |
|---|---|---|
| [arquitectura.md](arquitectura.md) | Explicación | Glosario, componentes, camino de un request, ciclo de vida de un incidente, fronteras de confianza, tabla de lo diseñado y lo construido |
| [decisiones.md](decisiones.md) | Explicación | Fallas del primer diseño, cambios que las resuelven y estado de cada uno; decisiones técnicas y su razón |
| [validaciones.md](validaciones.md) | Referencia | La reproducción y las cinco validaciones del parche: qué exige cada una, qué no detecta, cuándo se omite; el runner; el autotest |
| [operacion.md](operacion.md) | Guía de tareas y referencia | Instalación, demo incorporado, otra aplicación, comandos, puertos, secretos, variables, archivos, tests, recuperación |
| [resultados.md](resultados.md) | Referencia | Todo lo medido, con fecha, máquina, método, muestra y archivo de datos. Única fuente de cifras |
| [limites.md](limites.md) | Explicación | Lista única de límites, puntos ciegos y partes no construidas, por componente |
| [proceso.md](proceso.md) | Explicación | Cómo se construyó y revisó el proyecto, y cómo reproducir la auditoría |
| [fuxa.md](fuxa.md) | Guía de tareas | Demo sobre FUXA v1.2.9 (`immune fuxa`): comandos y qué hace cada uno |
| [openemr.md](openemr.md) | Guía de tareas y explicación | Ejemplo sobre OpenEMR 8.2.0 sin modificar: preparación, qué agrega el runtime genérico para PHP y MariaDB, mecanismos de detección |

El inicio rápido está en el [README de la raíz](../README.md).

## Contratos (en inglés)

| Documento | Tipo | Contenido |
|---|---|---|
| [contracts/README.md](../contracts/README.md) | Referencia | Procesos, puertos, redes, protocolos, headers, tipos de evento |
| [contracts/product.md](../contracts/product.md) | Referencia | Esquema de `.immune/config.yaml`, CLI, runtime genérico, comportamiento ante fallas |
| [contracts/interfaces.md](../contracts/interfaces.md) | Referencia | Interfaces entre `pipeline`, `patcher` y `sim` |
| `contracts/openapi.yaml`, `contracts/schemas/` | Referencia | OpenAPI de la tienda de demostración; esquemas JSON de evidencia, PoC y regla |

## Módulos (en inglés)

Cada README describe propósito, forma de ejecución, archivos, configuración, comportamiento, tests y límites del
módulo.

| Módulo | README |
|---|---|
| CLI `immune` | [immune/README.md](../immune/README.md) |
| Aplicación de demostración Tienda | [victim/README.md](../victim/README.md) |
| Gateway | [gateway/README.md](../gateway/README.md) |
| Oráculos en proceso | [shadow/README.md](../shadow/README.md) |
| Oráculos fuera del proceso | [sidecar/README.md](../sidecar/README.md) |
| Fleet | [fleet/README.md](../fleet/README.md) |
| Pipeline | [pipeline/README.md](../pipeline/README.md) |
| Patcher | [patcher/README.md](../patcher/README.md) |
| Dashboard | [dashboard/README.md](../dashboard/README.md) |
| Generador de tráfico y escenarios | [sim/README.md](../sim/README.md) |
| Modo de anticipación | [anticipate/README.md](../anticipate/README.md) |
| Laboratorio de Grafana | [labs/grafana-cve-2021-43798/README.md](../labs/grafana-cve-2021-43798/README.md) |
| Laboratorio de ScadaBR | [labs/scadabr-cve-2026-8602/README.md](../labs/scadabr-cve-2026-8602/README.md) |
| Aplicación de ejemplo notas | [examples/notas/README.md](../examples/notas/README.md) |
| Aplicación de ejemplo tareas-node | [examples/tareas-node/README.md](../examples/tareas-node/README.md) |
| Ejemplo sobre OpenEMR | [examples/openemr/README.md](../examples/openemr/README.md) |

Sin README propio: `waf/` (WAF de detección; ver [arquitectura.md](arquitectura.md#37-waf-de-detección-opcional)) y
`landing/` (página estática de presentación).

## Material del demo

| Ruta | Contenido |
|---|---|
| `docs/demo/metricas-tiempo-a-parche.json` | Datos de la medición de tiempos ([resultados.md](resultados.md)) |
| `docs/demo/selftest-2026-11-22.txt` | Salida del autotest de las validaciones ([resultados.md](resultados.md)) |
| `docs/demo/anticipacion-apache-2.4.49.md`, `docs/demo/anticipacion-apache-2.4.49.html` | Reporte del modo de anticipación sobre Apache httpd 2.4.49 |
| [demo/respuestas/](demo/respuestas/README.md) | Listas de defectos plantados de las tres aplicaciones de demostración |
| `docs/demo/dashboard/` | Capturas del panel |
| `docs/demo/pitch.html`, `docs/demo/presentacion.html` | Material de presentación |
