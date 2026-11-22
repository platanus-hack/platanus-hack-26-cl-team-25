# Validaciones del parche

Tipo de documento: referencia. Describe el paso de reproducción y las cinco validaciones que un parche debe pasar
antes de desplegarse, qué garantiza cada una, qué no detecta, y cuándo se omite o falla sin rechazar el parche.

El código está en `pipeline/gates.py` (`GATES = ("policy", "properties", "poc", "tests", "legit")`),
`pipeline/policy.py`, `pipeline/properties.py` y `pipeline/runner.py`. El lugar de las validaciones en el ciclo
del incidente está en [arquitectura.md](arquitectura.md#5-ciclo-de-vida-de-un-incidente).

Un solo modelo propone el parche. No hay un segundo modelo revisor: deciden estas validaciones.

Este documento describe las validaciones de un stack levantado con `immune up` (`pipeline/gates.py`). La etapa
de parche para aplicaciones externas que usa el laboratorio de Grafana tiene otras cinco, descritas en la
sección 12.

## 1. Resumen

| Orden | Validación | Dónde corre | Qué exige | Se puede omitir |
|---|---|---|---|---|
| 0 | Reproducción | runner, release sin parche | El PoC dispara el oráculo del incidente 3 de 3 veces. Si no, no se pide ningún parche | No |
| 1 | `policy` | host, sobre el diff (no ejecuta código de la app) | El diff respeta una política sintáctica | No |
| 2 | `properties` | runner, release parchado | Propiedades positivas de la clase del defecto | No |
| 3 | `poc` | runner, release parchado | El PoC y sus variantes no disparan ningún oráculo | No |
| 4 | `tests` | runner, release parchado | Pasa la suite de la aplicación (`tests.command`) | Sí, sin `tests.command` |
| 5 | `legit` | runner, antes y después | El comportamiento legítimo no cambia y cubre la ruta parchada | No; puede fallar sin rechazar |

Reglas comunes (`Validator.validate`):

- Un diff vacío o que no aplica se rechaza antes de cualquier validación. El rechazo se informa como `policy`.
- Las validaciones corren en orden y el proceso se detiene en la primera que falla.
- Una validación que lanza una excepción cuenta como fallida.
- El detalle de cada resultado se publica en el bus (`gate.result`) y se entrega al modelo en el intento
  siguiente.
- Dos situaciones no rechazan el parche pero limitan `autopatch` a `pr`, es decir, el pull request queda abierto
  y no se hace merge automático: `tests` omitida, y `legit` sin cobertura en los casos que se indican abajo.

## 2. Reproducción

Antes de pedir un parche, `Validator.reproduce` ejecuta el PoC tres veces sobre el release que está en
producción. Las tres ejecuciones deben disparar el tipo de oráculo del incidente y, cuando el incidente tiene un
archivo de origen, ese archivo debe aparecer en la pila del evento. El mismo oráculo disparado en otro archivo es
otro defecto, no una reproducción.

En la misma ejecución se prueban las variantes del PoC. Solo las que disparan el oráculo en el release sin parche
se cuentan para la validación `poc`.

Si el PoC no reproduce 3 de 3, no se pide ningún parche: sin un PoC fiable no hay con qué validarlo. El pipeline
publica la regla incorporada y cierra el incidente como `rule_only` con `outcome_detail: escalated`
(`Pipeline.escalate` en `pipeline/orchestrator.py`). El incidente queda contenido y a la espera de una persona;
evidencia nueva para el mismo punto lo reabre.

Qué no garantiza: la comprobación del archivo se omite cuando el incidente no tiene archivo de origen. Es el caso
del runtime genérico, donde los oráculos observan desde fuera del proceso y la evidencia no trae pila.

## 3. `policy`

Comprobación del diff en el host, comparando los árboles sintácticos de cada archivo antes y después
(`pipeline/policy.py`). No ejecuta código de la aplicación. Nunca se omite.

Rechaza un diff que:

- toca algo que no sea un archivo `.py` existente bajo `app.source_dirs`;
- cambia más de 120 líneas o más de 4 archivos (`POLICY_MAX_LINES`, `POLICY_MAX_FILES`);
- agrega imports;
- agrega acceso dinámico, a procesos, a red o al entorno (`eval`, `exec`, `__import__`, `importlib`, `os.environ`,
  `getattr` con nombre calculado, entre otros);
- agrega acceso a archivos con una ruta absoluta literal, o una constante que nombra un directorio del sistema;
- agrega lecturas del request o parámetros nuevos en un handler;
- compara un valor contra un literal contra el que la aplicación no comparaba antes: comparaciones, pertenencia,
  búsquedas en literales de diccionario, conjunto o lista, casos de `match`, y nombres ligados a esos literales;
- quita comprobaciones de 401 o 403;
- agrega cadenas de alta entropía.

Para código que no es Python la comprobación es léxica (`pipeline/generic.py`): imports (incluidos `include` y
`require` de PHP), tokens peligrosos (por ejemplo `shell_exec`, `unserialize` o `curl_exec` en PHP), acceso
calculado a miembros, cantidad de referencias a autenticación (entre ellas `aclCheckCore` y `verifyCsrfToken`, de
modo que un parche que quita una de esas comprobaciones se rechaza), entropía, y prohibición de tocar archivos de
tests o de dependencias.

**Es una heurística sobre la sintaxis, no una prueba.** No sigue el flujo de datos. No detecta:

- un literal pasado como argumento a una función auxiliar que lo compara, desempaquetado de una tupla, devuelto
  por una función o construido con formato en tiempo de ejecución;
- una comprobación que no necesita literal, como una longitud o un hash del valor;
- una puerta trasera semántica que no requiere literal, import ni lectura nueva del request;
- en código que no es Python: casos especiales por valor, rutas nuevas y lecturas nuevas del request.

Las otras cuatro validaciones juzgan comportamiento, no sintaxis.

## 4. `properties`

Propiedades positivas de la clase del defecto, sobre el release parchado, en el runner
(`pipeline/properties.py`). Todo se deriva del incidente, del perfil de la aplicación y del manifiesto; nada
nombra una ruta concreta. Nunca se omite, y falla si un caso queda vacío (por ejemplo, si no hay archivos
legítimos con los que comparar).

| Clase | Propiedad exigida |
|---|---|
| `sqli` | La estructura de la consulta ejecutada es idéntica para 14 entradas con metacaracteres (`SQL_META`) y dos valores benignos; el estado HTTP no cambia; `O'Brien` llega intacto a la base |
| `traversal` | Ninguna de 14 entradas de traversal (`TRAVERSAL`) abre un archivo fuera de las raíces permitidas; todo archivo legítimo que el release sin parche servía devuelve bytes idénticos |
| `idor` | El dueño recibe 2xx con solo datos propios; otro usuario de la semilla y un usuario nuevo reciben 403 o 404 sin datos ajenos; el estado para un anónimo no cambia |

Qué no garantiza: las propiedades se evalúan sobre esas entradas fijas, más las derivadas del incidente. Un
parche puede cumplirlas y seguir siendo vulnerable a una entrada fuera de esos conjuntos. Las clases cubiertas
son tres; un incidente de otra clase no tiene propiedades propias.

## 5. `poc`

El PoC y cada variante distinta que disparó el oráculo en el release sin parche se ejecutan sobre el release
parchado. Ninguno puede disparar un oráculo de ningún tipo (`gate_poc`). Nunca se omite.

Origen de las variantes:

- `patcher.variants` (`patcher/variants.py`): entre 0 y 40 requests distintos, generados por mutadores
  deterministas (otras codificaciones, otros payloads de la clase). No se rellena hasta un mínimo, y ninguna
  variante es igual al PoC. Para los incidentes de la tienda de demostración produce 31 variantes de `sqli`, 26
  de `traversal` y 26 de `idor`.
- `pipeline/poc.py` (`mutate`): mutaciones incorporadas: hasta 8 para `sqli` y `traversal`; para `idor`, una por cada canario del manifiesto para ese parámetro más dos identificadores vecinos.
- El corpus de la clase (`<runtime>/corpus/<clase>.jsonl`): valores confirmados en incidentes anteriores.

Las tres fuentes se deduplican entre sí.

Qué no garantiza: es tan fuerte como los oráculos. Una variante que explota el defecto de un modo que ningún
oráculo observa pasa como limpia. Las variantes que no dispararon antes del parche no se cuentan.

## 6. `tests`

Ejecuta `tests.command` de `.immune/config.yaml` en el runner, sobre el release parchado, con directorio de
trabajo `/app`. Código de salida 0 significa que pasa.

Si el proyecto no define `tests.command`, la validación se informa como omitida (`skipped`) y `autopatch` queda
limitado a `pr`.

Qué no garantiza: lo que la suite de la aplicación no prueba.

## 7. `legit`

Comprueba que el parche no cambia el comportamiento legítimo. Tiene dos modos.

**Con `scenarios` configurado.** El módulo de escenarios se ejecuta sobre el release sin parche y sobre el
parchado. Cada paso debe dar el mismo estado y el mismo cuerpo, y al menos un paso debe cubrir la ruta parchada.

| Situación | Resultado |
|---|---|
| Algún paso difiere, o un escenario falla en el release parchado | Rechaza el parche |
| El módulo de escenarios no se puede importar, o un escenario ya falla sin parche | Rechaza el parche |
| Ningún paso cubre la ruta parchada y el módulo declara `PARTIAL_COVERAGE = True` | Falla sin rechazar: `autopatch` limitado a `pr` |
| Ningún paso cubre la ruta parchada y el módulo no declara cobertura parcial | Rechaza el parche |

`immune init` genera escenarios solo de rutas GET y los marca con `PARTIAL_COVERAGE = True`
(`immune/initsteps/scenarios.py`).

**Sin `scenarios`.** Se repiten, antes y después del parche, los GET limpios con respuesta 200 que el gateway
grabó (`<runtime>/recordings/requests.jsonl`: el más reciente por ruta, consulta y usuario, hasta 200). Si las respuestas
difieren, rechaza el parche. Si no hay grabaciones o ninguna cubre la ruta parchada, falla sin rechazar y
`autopatch` queda limitado a `pr`.

Para la tienda de demostración los escenarios son cinco, guionados y deterministas, en `sim/scenarios.py`:
`anonymous_catalog`, `new_customer_obrien`, `existing_customer`, `second_customer`, `admin`. **El corpus legítimo
del demo es sintético**: no es tráfico de usuarios reales.

En el runtime genérico, la clave `legit.normalize` de `.immune/config.yaml` es una lista de expresiones regulares
cuyo texto coincidente se reemplaza antes de comparar los cuerpos (`norm_body` en `pipeline/jobshape.py`). Sirve
para valores que cambian en cada sesión, como tokens CSRF y marcas de tiempo. Una expresión demasiado amplia oculta
diferencias reales.

Qué no garantiza: un cambio de comportamiento en una ruta o con una entrada que ningún escenario ni grabación
ejercita. En el modo de grabaciones solo se repiten requests GET.

## 8. El runner

Todo código de la aplicación que ejecutan la reproducción y las validaciones corre en un contenedor
(`pipeline/runner.py`): `docker run --rm --network none --read-only`, capacidades eliminadas,
`no-new-privileges`, límites de pids, memoria y CPU, el release montado de solo lectura en `/app`, y `runtime/`
y `.git` ocultos con un tmpfs. No existe un modo que ejecute ese código como subproceso del host.

El resultado vuelve por stdout en una línea `@@RESULT@@ <nonce> <json>`, con un nonce aleatorio por ejecución que
el módulo de entrada retira del trabajo antes de importar código de la aplicación. Esto resiste a código que
imprime una línea de resultado falsa. No resiste a código que inspecciona su propio intérprete para encontrar el
nonce; la validación `policy` rechaza las construcciones que eso requeriría.

## 9. Después de las validaciones

Pasar las cinco validaciones no cierra el incidente. Después del despliegue hay una verificación
(`pipeline/verify.py`): el PoC y sus variantes no disparan ningún oráculo sobre el release desplegado, y el mismo
request enviado por el gateway desde una sesión nueva es reenviado a prod, lo que se confirma con
`forwarded: true` en el `prodlog` del gateway. Si falla, la regla se vuelve a publicar.

El despliegue tiene sus propios controles, el canario de despliegue y la observación de la tasa de 5xx con
rollback, descritos en [operacion.md](operacion.md#despliegue-y-rollback).

## 10. Parches de respaldo

`patcher/fallbacks/` contiene 7 diffs escritos a mano, uno por defecto de la tienda de demostración. Se usan solo
si la llamada al modelo falla, vence o devuelve un diff vacío, o con `PATCHER_FORCE_FALLBACK=1`. Pasan por las
mismas cinco validaciones. Se publican con `source: "fallback"` en el bus, el dashboard los muestra como
"Fuente: fallback", y el cuerpo del pull request y el mensaje de commit lo indican. Un origen desconocido o
ausente se informa como `unknown`, nunca como `llm`. El runtime genérico no tiene parches de respaldo.

## 11. Autotest de las validaciones

`pipeline/selftest.py` comprueba que las validaciones aceptan lo correcto y rechazan lo incorrecto, sobre el
release `t0` de la tienda de demostración y en contenedores runner reales. Necesita Docker. No llama al modelo.

```bash
.venv/bin/python -m pipeline.selftest
```

Qué hace:

1. Detona cada entrada de `docs/demo/respuestas/tienda.md` y deriva el incidente correspondiente.
2. Aplica los 7 parches de `patcher/fallbacks/`. Cada uno debe pasar las cinco validaciones.
3. Aplica los 15 parches inadecuados del catálogo `pipeline/fixes.py`. Cada uno debe ser rechazado por la
   validación que el catálogo indica: 7 por `policy`, 5 por `properties`, 1 por `poc`, 1 por `tests`, 1 por
   `legit`.

El catálogo contiene además 3 parches adecuados, uno por clase, que el autotest no ejecuta; los usa el patcher
sustituto de los tests (`pipeline/stub_patcher.py`), y `pipeline/tests/test_policy_bypass.py` comprueba que pasan
`policy`. El código de salida es 0 solo si se cumplen todas las expectativas. El resultado de la
última ejecución registrada está en [resultados.md](resultados.md).

Alcance: son parches escritos a mano para la tienda de demostración, no salidas del modelo. El autotest prueba
las validaciones contra un conjunto conocido; no mide cuántos parches inadecuados de un modelo dejarían pasar.

## 12. Validaciones de la etapa de parche para aplicaciones externas

`pipeline/extfix.py` (`GATES = ("policy", "build", "tests", "poc", "legit")`) valida el parche de una aplicación
externa descrita por un archivo `target.yaml`. Solo la usa el laboratorio de Grafana
(`labs/grafana-cve-2021-43798/target.yaml`). Comparte nombres con las validaciones anteriores, pero no su
contenido. Corren en orden; la salida de la que falla se entrega al modelo en el intento siguiente.

| Validación | Dónde corre | Qué exige |
|---|---|---|
| `policy` | host, sobre el diff | Diff no vacío; solo archivos bajo `source_dirs` que no terminen en `_test.go`; como máximo `policy.max_files` archivos y `policy.max_lines` líneas (2 y 60 por defecto); no agrega `"os/exec"`, `"net/http"`, `"unsafe"` ni directivas `//go:` |
| `build` | contenedor `sandbox.image`, `--network none` | El comando `sandbox.build` termina con código 0 y produce el artefacto |
| `tests` | el mismo contenedor | El comando `sandbox.tests` termina con código 0 |
| `poc` | contenedor candidato con el artefacto y la configuración del clon | El request original y las mutaciones de `pipeline/poc.py` no producen ningún marcador en la respuesta y, con `oracles` configurado, ningún evento `file`, `proc` o `net` del observador del sidecar |
| `legit` | candidato frente al clon actual | Cada ruta de `legit` da el mismo estado y, donde se declara `compare: body`, el mismo cuerpo |

Qué no garantiza:

- `policy` es una lista corta de cadenas, escrita para Go. No hace el análisis sintáctico de la sección 3.
- No hay validación `properties`.
- `poc` solo ve lo que ven los oráculos configurados; en el laboratorio de Grafana, los archivos protegidos de
  `sidecar.json`.
- `legit` compara las rutas que alguien escribió en `target.yaml`: 7 en el laboratorio.
- No tiene autotest con parches inadecuados, y sus tests (`pipeline/tests/test_extfix.py`) cubren `policy`, el
  prompt y los eventos publicados, no `build`, `tests`, `poc` ni `legit`.
