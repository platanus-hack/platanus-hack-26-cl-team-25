# Resultados medidos

Tipo de documento: referencia. Reúne todo lo que se midió, con fecha, máquina, método, tamaño de muestra y
archivo de datos. Es la única fuente de cifras de la documentación: los demás documentos enlazan aquí.

Cada resultado indica uno de tres niveles de respaldo:

- **Con datos**: hay un archivo en el repositorio del que se puede recalcular la cifra.
- **Observado una vez, sin datos crudos en el repositorio**: alguien del equipo lo ejecutó y anotó el resultado;
  no hay archivo que lo respalde.
- **Medido en local por el equipo, sin datos crudos en el repositorio**: el resultado figura en el README de un
  laboratorio o en una guía, sin fecha, máquina ni número de corridas registrados, y sin archivo que lo respalde.
  Este documento lo cita con su fuente y no lo verifica.

## Advertencia sobre las cifras de tiempo

Las mediciones de tiempo de las secciones 1 y 3 son del 2026-11-21. Son anteriores a las correcciones de la
auditoría del 2026-11-22. La sección 6 es una corrida posterior, de un solo ciclo de siete incidentes, con
condiciones distintas.

También son anteriores a tres cambios del código actual que afectan a esos tiempos: el canario de despliegue,
que agrega hasta `CANARY_S` segundos (8 por defecto; 2 sin tráfico) antes del cambio de upstream; las reglas de
alcance `param_present`, que detonan todo request que trae el parámetro; y el cierre `escalated` de un PoC que no
reproduce 3 de 3 ([arquitectura.md](arquitectura.md#5-ciclo-de-vida-de-un-incidente)).

En esa fecha, la lista de defectos plantados de la tienda estaba dentro de `victim/`, el árbol que el generador
de parches podía leer. La evidencia que recibe el modelo ya contiene el archivo y la línea
de la pila, y quienes deciden son las validaciones; pero no se puede demostrar que el modelo no leyó ese archivo.
Desde el 2026-11-22 las listas viven en `docs/demo/respuestas/`, fuera de las rutas de todo release.

## 1. Tiempo de incidente a parche en producción

| | |
|---|---|
| Nivel | Con datos: `docs/demo/metricas-tiempo-a-parche.json` |
| Fecha | 2026-11-21 |
| Máquina | ARM64, 4 núcleos, compartida con otros trabajos |
| Aplicación | Demo incorporado (Tienda): 7 defectos plantados × 3 rondas, un incidente a la vez |
| Método | `python -m immune.metrics`, a partir de las marcas de tiempo de los eventos del bus |
| Muestra | n = 21 incidentes |

Resultado: **21 de 21 incidentes parchados**, todos con `source: llm` y todos en el primer intento.

Tiempos desde que se abre el incidente (evento `incident.opened`), en segundos. La espera en cola anterior a ese
evento está en el campo `queue` del archivo y no se incluye:

| Hito | Evento del bus | Mediana | Mínimo | Máximo |
|---|---|---|---|---|
| Regla activa en el gateway | `rule.active` | **1.9** | 1.8 | 3.6 |
| El modelo devuelve un diff | primer `patch.diff` | 10.0 | 8.6 | 13.8 |
| Validaciones pasadas y merge | `pr.merged` | 23.1 | 20.3 | 29.1 |
| Release parchado atendiendo producción | `upstream.switched` posterior al merge | **24.9** | 22.2 | 31.0 |
| Verificado a través del gateway | `verify.result` | **51.3** | 48.8 | 58.4 |

Cómo leerlo:

- Aplica la advertencia de arriba.
- Son defectos plantados en una aplicación de demostración pequeña, con archivo y línea en la evidencia. No
  predicen el tiempo ni la tasa de éxito sobre una aplicación real.
- El tramo entre "en producción" y "verificado" incluye la ventana de observación del despliegue (20 segundos por
  defecto).
- La medición no incluye el canario de despliegue, que no existía en esa fecha.
- Una sola serie, en una máquina compartida: no hay intervalo de confianza entre series.

## 2. Tests y autotest

| | |
|---|---|
| Nivel | Observado; el resultado se reproduce con los comandos de [operacion.md](operacion.md#tests) |
| Fecha | 2026-11-22, después de las correcciones de la auditoría |
| Máquina | La del demo (ARM64, 4 núcleos) |

### Tests

| Medición | Resultado |
|---|---|
| Tests que recolecta `pytest` en la raíz (los 12 `testpaths` de `pytest.ini`) | 912 |
| `.venv/bin/pytest -q -m "not live"` | 904 pasan, 2 omitidos (`skip`), 6 deseleccionados |
| Los 6 tests `live` (llaman al modelo) | No se ejecutaron |
| Suite propia de `examples/notas` | 33 tests |
| `pyflakes` sobre el Python versionado | Sin avisos |

La ejecución incluye los tests que usan Docker (`fleet`, integración de `sidecar`, integración de `pipeline`,
`anticipate`). No hay integración continua: estas cifras son de una ejecución manual.

### Autotest de las validaciones

`python -m pipeline.selftest` ([validaciones.md](validaciones.md#11-autotest-de-las-validaciones)), 2026-11-22:

| Conjunto | Esperado | Resultado |
|---|---|---|
| 7 parches escritos a mano (`patcher/fallbacks/`) | Pasan las cinco validaciones | 7 de 7 |
| 15 parches inadecuados (`pipeline/fixes.py`): 7 `policy`, 5 `properties`, 1 `poc`, 1 `tests`, 1 `legit` | Rechazados por la validación indicada | 15 de 15 |

57 trabajos de runner, 47 segundos. La salida completa de esa ejecución está en
[`demo/selftest-2026-11-22.txt`](demo/selftest-2026-11-22.txt). Son parches escritos a mano para la tienda de demostración, no salidas del
modelo.

## 3. Otras verificaciones del 2026-11-21

Todas son del nivel **observado una vez, sin datos crudos en el repositorio**. Aplica la advertencia sobre las
cifras de tiempo.

| Qué | Resultado |
|---|---|
| `immune init` + `immune up` sobre `examples/notas` | `init` terminó en `READY` en 47 s. Sus 4 defectos plantados quedaron parchados, entre 22 y 63 s hasta producción |
| Runtime genérico sobre `examples/tareas-node` | Stack arriba en 11 s. La inyección SQL quedó parchada en 37 s. El traversal y el IDOR se detectaron, con regla y pull request abierto, pero sin merge: no había tráfico legítimo grabado que cubriera la ruta. Es el comportamiento previsto de la validación `legit` |
| Auditoría de clase | Con 3 requests enviados, uno por clase, quedaron parchados los 7 defectos de la tienda; 4 los encontró la auditoría sin que nadie los ejerciera |
| Inyección de fallas con 20 requests por segundo de tráfico legítimo | Tabla completa en la sección 11 de [`contracts/product.md`](../contracts/product.md): una ejecución por falla |
| Entradas malformadas al gateway (cuerpos grandes, URL largas, JSON inválido, bytes no UTF-8, muchos headers, clientes lentos, conexiones ociosas y simultáneas) | Sin caídas ni reinicios; memoria del gateway de 28 a 33 MB |

## 4. Modo de anticipación sobre Apache httpd 2.4.49

| | |
|---|---|
| Nivel | Con datos: `docs/demo/anticipacion-apache-2.4.49.md` y `docs/demo/anticipacion-apache-2.4.49.html`, regenerados el 2026-11-22 a partir del resultado guardado |
| Ejecución | 2026-11-21, 34 s, modelo `opus` |
| Método | `immune anticipate run apache-httpd-2.4.49` ([`anticipate/README.md`](../anticipate/README.md)) |

| Versión | Propiedades que cumple |
|---|---|
| 2.4.49 publicada | 14 de 21 |
| Parche sugerido por el modelo | 21 de 21 |
| 2.4.50, cambio oficial | 21 de 21 |

El parche sugerido y el oficial dan resultado idéntico en los 21 vectores y modifican la misma función,
`ap_normalize_path`.

Qué significa, y qué no:

- **Qué recibe el modelo:** producto y versión, el área del código, la clase de defecto con su mecanismo, un
  alcance de un archivo y pistas sobre qué comportamiento conservar. **No recibe** el identificador del aviso, la
  versión corregida, el diff oficial ni los vectores.
- **Los 21 vectores los escribió el equipo.**
- **"21 de 21" significa** que la función extraída, compilada contra un shim, devuelve el mismo valor de retorno y
  el mismo buffer de salida para esas 21 entradas. No es equivalencia de comportamiento de httpd. No se ejecuta
  ningún servidor.
- **CVE-2021-41773 es público** y casi con certeza está en los datos de entrenamiento del modelo. El resultado
  demuestra el mecanismo (revisar, parchar, validar, comparar), no un descubrimiento a ciegas.
- **La referencia tiene un defecto conocido:** el arreglo de 2.4.50 resultó incompleto (CVE-2021-42013) y se
  corrigió en 2.4.51. Coincidir con 2.4.50 no equivale a estar libre del defecto.

## 5. Casos sobre software de terceros

Todos son del nivel **medido en local por el equipo, sin datos crudos en el repositorio**, salvo donde se indica.
Ninguno tiene test automático de punta a punta. Las fallas son públicas o vienen de un aviso: los casos ejercitan
el mecanismo con el request del aviso, no un descubrimiento.

### Grafana 8.3.0, CVE-2021-43798

Fuente: `labs/grafana-cve-2021-43798/README.md`. Sin fecha, máquina ni número de corridas registrados.

| Qué | Resultado según la fuente |
|---|---|
| Ciclo completo (detección en el clon, regla, parche del modelo, validaciones en un contenedor sin red, merge en un clon local, blue/green, verificación) | Incidente cerrado como `patched` |
| Tiempos, con las cachés de compilación ya llenas | Regla a los 0,6 s; parche en producción a los 54 s |
| Validaciones | En una corrida la validación `tests` rechazó el primer intento (rompía `Test_GetPluginAssets`) y el segundo pasó |
| Vigilante de prod, con el gateway en `passthrough` | El request llega a prod, se publica la alerta, el clon lo confirma y el incidente cierra como `patched`. El mismo request directo al puerto de prod alerta como tráfico que no pasó por el gateway |

Lo que el caso no muestra: los oráculos `proc`, `net` y `sql` contra una falla real (este CVE es de lectura de
archivos); un pull request en GitHub; el canario de despliegue.

### ScadaBR 1.2.0, CVE-2026-8602

Fuente: `labs/scadabr-cve-2026-8602/README.md` y los scripts del laboratorio. Sin cifras de tiempo.

| Qué | Resultado según la fuente |
|---|---|
| Detección | Una escritura anónima en `/ScadaBR/httpds` se detona en el clon y el oráculo de `sidecar/httpds` confirma que un punto de datos la consumió |
| Regla | `scope: all` con `identity: untrusted` sobre `/ScadaBR/httpds` |
| Parche | En una corrida contra el código fuente de ScadaBR, el modelo propuso en `HttpDataSourceServlet` una comprobación `Common.getUser(request) == null` que responde 404 |
| Validación del parche (`labs/scadabr-cve-2026-8602/verify_patch.sh`) | El script compila el servlet parchado dentro de un contenedor candidato y comprueba dos cosas: el request anónimo recibe 404 y una sesión autenticada sigue escribiendo. No hay registro de su salida en el repositorio |

Lo que el caso no muestra: la credencial de los dispositivos legítimos la modela el gateway, porque ScadaBR 1.2.0
no tiene ninguna en ese endpoint; el contenedor de prod del laboratorio no se reemplaza por el parchado; no hay
arreglo del fabricante con el que comparar.

### OpenEMR 8.2.0

Fuente: [openemr.md](openemr.md), sección "Lo verificado en vivo". Sin fecha ni máquina registradas.

| Request contra un clon completo (MariaDB, OpenEMR con traza, sidecar) | Veredicto según la fuente |
|---|---|
| Login, buscador de pacientes, API REST, FHIR `Patient`, consulta con `O'Brien` | `clean` |
| Inyección SQL de prueba (un script de prueba, no código de OpenEMR) | `oracle` `sql`, con pila PHP |
| Traversal de prueba hacia `/etc/hostname` (un script de prueba) | `oracle` `file`, con pila PHP |
| Sonda de inyección SQL contra la búsqueda real de OpenEMR | `clean`: esa consulta está parametrizada |

La guía describe además el mecanismo de detección previsto para cinco CVE de OpenEMR 8.2.0. El repositorio no
contiene un resultado registrado de esas cinco detecciones ni de un parche desplegado sobre OpenEMR.

Con datos: `immune/tests/test_mysql_runtime.py` comprueba, sin Docker, que la configuración del ejemplo valida y
que el perfil no sobrescribe archivos de OpenEMR.

### FUXA v1.2.9

Fuente: [fuxa.md](fuxa.md). No hay mediciones. `immune fuxa demo` usa evidencia sintética, marcada como tal: no
registra la detección de un ataque real. Con datos: los tests de `immune/tests/test_fuxa.py`, que forman parte de
la suite de la sección 2.

## 6. Corrida con atacante y tráfico legítimo, posterior a la auditoría

| | |
|---|---|
| Nivel | Con datos: `docs/demo/corrida-2026-11-22.json` (salida de `immune.metrics` y conteos de la grabación del gateway) y `docs/demo/corrida-2026-11-22-atacante.log` |
| Fecha | 2026-11-22, después de las correcciones de la auditoría |
| Máquina | La del demo (ARM64, 4 núcleos, compartida) |
| Método | `deploy/record_demo.sh`: `immune reset`, tráfico legítimo a 3 requests por segundo (`sim.legit`) y el atacante de demostración (`sim.attacker`) hasta que los siete exploits quedaron bloqueados dos rondas seguidas |
| Muestra | n = 7 incidentes, una sola corrida |

Resultado: **7 de 7 incidentes parchados y verificados**, los 7 con `source: llm` y en el primer intento. El
atacante hizo 56 rondas (392 intentos) y **ninguno obtuvo datos de producción**: según la verificación contra la
base y el contenedor de producción, cada intento fue bloqueado o respondido por un clon con datos sintéticos.

Tiempos desde `incident.opened`, en segundos (misma definición que la sección 1):

| Hito | Mediana | Mínimo | Máximo |
|---|---|---|---|
| Regla activa en el gateway | **4.3** | 2.4 | 7.0 |
| El modelo devuelve un diff | 13.3 | 11.1 | 18.1 |
| Validaciones pasadas y merge | 38.9 | 27.8 | 60.3 |
| Release parchado atendiendo producción | **45.2** | 30.4 | 64.6 |
| Verificado a través del gateway | **78.5** | 63.4 | 100.4 |

Daño colateral sobre el tráfico legítimo, medido en la grabación del gateway: de 4551 requests de clientes de la
semilla, **82 recibieron un 404**. 74 fueron pedidos de un cliente sobre **sus propios** pedidos creados después
de la semilla, mientras estaba activa la regla de un IDOR (ver [limites.md](limites.md#gateway)); 8, requests
sospechosos sin un clon libre para detonarlos. El generador de tráfico legítimo contó 31 violaciones.

Cómo leerlo:

- Son los mismos siete defectos plantados de la sección 1, con el mismo modelo de amenaza. Esta corrida no
  demuestra generalización; muestra que el ciclo sigue funcionando después de la auditoría, con carga legítima y
  un atacante activo al mismo tiempo.
- Los tiempos son más altos que los de la sección 1 porque la máquina atendía también al atacante, al tráfico
  legítimo y a la grabación del video. No son comparables uno a uno.
- Una sola corrida: no hay dispersión entre corridas.

## 7. Lo que no se midió

- Latencia que agrega la detonación a un request sospechoso, y latencia del gateway para un request limpio.
- Latencia que agrega el WAF de detección a cada request limpio, y su tasa de anomalías sobre tráfico legítimo.
- Efecto de una regla `param_present` sobre el tráfico legítimo de ese parámetro.
- El canario de despliegue con tráfico real: solo tiene tests ([arquitectura.md](arquitectura.md#7-diseñado-y-construido)).
- Sobrecarga del vigilante de prod sobre el contenedor observado.
- Tasa de falsos positivos del clasificador y de los oráculos sobre tráfico real.
- Tasa de éxito del parche automático fuera de los defectos plantados en las tres aplicaciones de demostración y
  de las corridas citadas en la sección 5.
- Cualquier cifra en x86_64, con más carga, o con una aplicación en producción real.
- Comportamiento de los pull requests contra GitHub real.

Las cifras de sobrecarga que aparezcan en `sidecar/README.md` provienen de una ejecución no registrada de
`sidecar/tests/bench.py`, que es un script de medición y no un test; no forman parte de estos resultados.
