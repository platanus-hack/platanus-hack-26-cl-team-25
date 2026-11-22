# Operación

Tipo de documento: guía de tareas y referencia. Cubre instalación, comandos, puertos, secretos, archivos de
estado, cómo correr los tests, cómo se recupera el sistema y qué falta en la operación.

El esquema completo de `.immune/config.yaml` y los protocolos entre procesos están en
[`contracts/`](../contracts/README.md). La arquitectura está en [arquitectura.md](arquitectura.md).

## Requisitos

| Requisito | Para qué | Obligatorio |
|---|---|---|
| Linux con Docker Engine utilizable sin `sudo` | Todo | Sí |
| Plugin Docker Compose | `immune up` | Sí |
| git | Construir y aplicar parches | Sí |
| Python 3.12 o posterior con el módulo `venv` (Debian y Ubuntu: `python3-venv`) | La CLI y los procesos del host | Sí |
| Red hacia PyPI, Docker Hub y los mirrors de Debian, una vez | Construir el entorno y las imágenes | Sí |
| CLI de Claude Code (`claude`) con sesión iniciada | Pasos con modelo de `immune init` y parches automáticos | No |
| GitHub CLI (`gh`) con sesión iniciada | `repo.target: github` | No |
| Imagen `immune-cbuild:1` | `immune anticipate` | No |
| Imágenes fijadas de OpenEMR y MariaDB | El ejemplo `examples/openemr` | No |

`immune doctor --prereqs` informa cuáles están presentes.

Sin la CLI `claude`, los ataques se detectan y se contienen con una regla, pero no se parchan (salvo los siete
defectos de la tienda de demostración, que tienen parche de respaldo).

## Instalar

```bash
git clone https://github.com/platanus-hack/platanus-hack-26-cl-team-25.git immune
cd immune
./install.sh
```

`install.sh` hace, en orden: comprueba Docker, Compose, git y Python; crea `.venv` a partir de
`deploy/requirements.txt`; construye las imágenes `immune-base:1` e `immune-sidecar:1` desde `deploy/`; enlaza
`bin/immune` en `~/.local/bin/immune`; y ejecuta `immune doctor --prereqs`.

Propiedades:

- No usa `sudo`. Cuando falta algo, dice qué instalar y termina.
- Se puede volver a ejecutar. Cada paso se salta si ya está hecho.
- Las imágenes se construyen en la máquina. La construcción descarga `python:3.12-slim` de Docker Hub y paquetes de
  PyPI y de los mirrors de Debian. No se descarga ninguna imagen de Immune de un registro.
- Reconstruye el entorno virtual cuando cambia `deploy/requirements.txt`, y una imagen cuando cambia ese archivo o
  su Dockerfile.
- No reemplaza un enlace `~/.local/bin/immune` que apunte a otro checkout: avisa y lo deja.

| Variable de `install.sh` | Efecto | Por defecto |
|---|---|---|
| `IMMUNE_BIN_DIR` | Directorio donde se crea el enlace `immune` | `~/.local/bin` |
| `IMMUNE_VENV_DIR` | Directorio del entorno virtual. `bin/immune` y la CLI leen la misma variable, así que debe estar definida también al ejecutar | `.venv` en el checkout |
| `PYTHON` | Intérprete con el que se crea el entorno virtual | `python3` |
| `IMMUNE_SKIP_IMAGES=1` | No construye imágenes | sin definir |
| `IMMUNE_WITH_ANTICIPATE=1` | Construye también `immune-cbuild:1` | sin definir |
| `IMMUNE_WITH_OPENEMR=1` | Descarga las imágenes fijadas de OpenEMR y MariaDB (`openemr_images` en `immune/doctor.py`) y agrega `--openemr` a la comprobación de requisitos | sin definir |

Probado en un Ubuntu 24.04 ARM64 limpio. No probado en x86_64 ni en otras distribuciones.

Las imágenes de los laboratorios (`immune-strace:1`, `immune-bpftrace:1`, `immune-gobuild:1`, `immune-waf:1`) no
las construye `install.sh`: las construye el `lab.sh` de cada laboratorio la primera vez.

Si `~/.local/bin` no está en el `PATH`, el comando también funciona como `bin/immune` desde el checkout.

## Levantar el demo incorporado

El demo incorporado es el proyecto `tienda`: la aplicación "Tienda" de `victim/`, configurada en
`.immune/config.yaml` en la raíz del repositorio.

```bash
immune up        # desde la raíz del checkout; desde otro directorio: immune up --project /ruta/al/checkout
immune status
```

`immune up` genera los datos, crea el release `t0`, levanta gateway y dashboard con Docker Compose, arranca
`fleet` y `pipeline` y espera a que haya un release en producción y el pool de clones completo. La última línea
empieza con `stack immune-tienda up:` e indica las URL, el modo y el valor efectivo de `autopatch`. Si ya existía
una corrida en disco, `up` la retoma y la línea empieza con `stack immune-tienda resumed`.
`immune status` termina con `healthy` y código de salida 0.

- Aplicación protegida, a través del gateway: `http://127.0.0.1:8080`
- Panel en vivo: `http://127.0.0.1:8090`

Para producir un incidente, envíe una de las peticiones de `docs/demo/respuestas/tienda.md`. Por ejemplo, la
inyección SQL en la búsqueda de productos:

```bash
curl -s "http://127.0.0.1:8080/api/products?q=zzzzzz%27%20OR%20%271%27%3D%271"
```

La respuesta proviene de un clon y contiene datos sintéticos. El panel muestra el incidente, la regla, el diff,
el resultado de cada validación y el despliegue. Para ver el resumen desde la terminal:

```bash
immune report
.venv/bin/python -m immune.metrics --bus http://127.0.0.1:8090
```

Para generar tráfico legítimo de fondo contra la tienda (desde la raíz del checkout, porque lee
`runtime/data/manifest.json`):

```bash
.venv/bin/python -m sim.legit --base http://127.0.0.1:8080 --duration 60
```

Para que un atacante automático repita en bucle los siete exploits documentados de la tienda (con una cuenta
recién registrada; cada tres rondas vuelve con cuenta y sesión nuevas), hasta que los siete queden bloqueados dos rondas seguidas:

```bash
.venv/bin/python -m sim.attacker --interval 1.5 --until-closed 2
```

Cada línea dice si el ataque fue bloqueado, si funcionó sobre un clon con datos sintéticos o si obtuvo datos
reales de producción; esto último se comprueba contra la base y el contenedor de producción. Los intentos
alimentan el panel "Bot atacante". Solo apunta al gateway de esta máquina.

Para grabar el video de respaldo de la demo (reset, tráfico legítimo, atacante y panel con la terminal al lado;
necesita Node con `playwright-core` y un Chromium):

```bash
PLAYWRIGHT_CORE_DIR=<directorio con node_modules/playwright-core> deploy/record_demo.sh
```

El guion de la presentación está en [demo/guion.md](demo/guion.md).

Para volver al estado inicial (datos nuevos, `t0` en producción, sin incidentes) y para detener todo:

```bash
immune reset
immune down
```

## Proteger otra aplicación

`immune init` adapta Immune a una aplicación Python ASGI que expone `openapi()` (FastAPI) y usa un archivo
SQLite. Para otros lenguajes `init` no genera nada: el perfil se escribe a mano, como los de
`examples/tareas-node/.immune/` y `examples/openemr/overlay/.immune/`. Ante un proyecto PHP con MySQL que ya tiene
`.immune/config.yaml`, `init` solo lo valida (comprobaciones 1 y 9 del doctor) y termina con `READY` o
`NEEDS ATTENTION`.

```bash
cd /ruta/a/su-app
immune init
immune up
```

`immune init` imprime una línea por paso y termina con `READY: immune up --project <dir>` (código de salida 0) o
con `NEEDS ATTENTION:` seguido de una lista corta (código 1). Pasos:

1. Detecta runtime, entrada ASGI, puerto, comando de tests y forma de despliegue.
2. Obtiene el OpenAPI importando la aplicación: primero en un contenedor `--network none`; si Docker no está
   disponible o ese intento falla, en un subproceso del host; y si tampoco, desde un archivo de especificación
   del proyecto (`openapi.yaml`, `swagger.json` y similares).
3. Lee el esquema de la base SQLite.
4. Clasifica las columnas en públicas, privadas y secretas, y les asigna dueño (`.immune/shadow/columns.yaml`).
5. Escribe `.immune/profile.py` y el bloque de autenticación.
6. Marca en el OpenAPI las rutas `x-owner-scoped` y los campos `x-sensitive`.
7. Construye los datos sintéticos de los clones y los escenarios legítimos.
8. Ejecuta `immune doctor`; ante fallas, devuelve el error al paso que corresponde, hasta 3 rondas.
9. Escribe los artefactos de despliegue y `.immune/report.md`.

Los pasos 4, 5 y 6 usan el modelo, con el mismo confinamiento que el generador de parches. El mínimo son 3
llamadas; cada paso reintenta hasta 3 veces. Con `--no-llm`, o cuando la CLI `claude` no está instalada (init lo
indica con un mensaje), se conservan los borradores heurísticos. Si el modelo falla tres veces en un paso y el
borrador valida, init termina en `READY` pero imprime `NOTE: LLM unavailable for step(s) …`.

`init` escribe `autopatch: pr` en la configuración: un parche que pasa las validaciones queda como pull request
abierto, con la regla activa. `immune autopatch merge` activa el merge y el despliegue automáticos; aun así, los
escenarios que genera `init` solo cubren rutas GET, y un parche en una ruta sin cobertura queda en `pr`
([validaciones.md](validaciones.md#7-legit)).

Revise `.immune/report.md` y los archivos generados antes de usar el resultado. `profile.py` lo escribe un modelo;
se comprueba con una lista estática de construcciones prohibidas y después se importa en el host, con el usuario
que ejecuta `init`. Los límites de `init` están en [limites.md](limites.md#immune-init-y-immune-doctor).

### Segundo proyecto en la misma máquina

Cada proyecto tiene su propio stack: proyecto de Compose, contenedores y redes llevan el prefijo
`immune-<name>`, y el estado vive en su propio directorio de runtime. Dos proyectos no pueden compartir puertos:
fije valores distintos en `ports:` de `.immune/config.yaml` del segundo. `immune up` falla al inicio, con el
puerto y la clave de configuración, si un puerto está ocupado por algo ajeno al stack.

Para `examples/notas`, que no trae `.immune/` ni base de datos:

```bash
cd examples/notas
../../.venv/bin/python scripts/init_db.py --db data/notas.db
immune init --yes
# si el demo incorporado está en marcha, agregue a .immune/config.yaml:
#   ports: {gateway: 8280, admin: 8281, dashboard: 8290, fleet: 8270}
immune up
```

Para `examples/tareas-node` (Node + Postgres, runtime genérico, perfil ya escrito, puertos 8180, 8181, 8190 y
8170):

```bash
immune up --project examples/tareas-node
```

Para OpenEMR 8.2.0 (PHP + MariaDB, runtime genérico, puertos 8280, 8281, 8290 y 8270), los pasos están en
[openemr.md](openemr.md).

### Laboratorios y demo de FUXA

No usan `immune up`. Cada uno levanta sus propios procesos y contenedores, con puertos distintos de los de un
stack; los dos laboratorios usan los mismos puertos de gateway y bus (18080, 18081, 18090), así que no corren a
la vez.

| Qué | Comandos | Documento |
|---|---|---|
| Grafana 8.3.0, CVE-2021-43798 | `labs/grafana-cve-2021-43798/lab.sh up\|check\|status\|down` | `labs/grafana-cve-2021-43798/README.md` |
| ScadaBR 1.2.0, CVE-2026-8602 | `labs/scadabr-cve-2026-8602/lab.sh up\|check\|status\|down` | `labs/scadabr-cve-2026-8602/README.md` |
| FUXA v1.2.9 | `immune fuxa baseline`, `up`, `status`, `watch`, `dashboard`, `demo`, `down` y los demás subcomandos de `immune/fuxa.py` | [fuxa.md](fuxa.md) |

`lab.sh up` necesita red la primera vez (imágenes, y en Grafana el código fuente y los módulos de Go).

## Referencia de comandos

Todos los comandos salvo `anticipate` y `fuxa` aceptan `--project DIR`. Sin él, `up`, `down`, `status`, `reset`,
`report`, `mode`, `autopatch`, `rollback`, `doctor` y `deploy` usan, en este orden: la variable `IMMUNE_PROJECT`; el directorio más cercano hacia
arriba que contenga `.immune/config.yaml`; y si no hay ninguno, el checkout de Immune (el demo incorporado).
`init` usa el directorio actual.

| Comando | Qué hace | Código de salida |
|---|---|---|
| `immune up` | Levanta el stack. Si ya existe una corrida en disco, la retoma sin volver a `t0` | 0; 1 si algo no arranca |
| `immune reset` | Vuelve a `t0`: datos nuevos, release inicial en producción, sin incidentes ni reglas | 0; 1 si algo no arranca |
| `immune down` | Detiene procesos del host y elimina los contenedores del proyecto | 0 |
| `immune status` | Resumen de salud: contenedores, `fleet`, `pipeline`, gateway, dashboard, release, clones, reglas | 0 sano; 1 si algo no está sano, incluido un `fleet` inalcanzable |
| `immune report [--json]` | Resumen desde el bus y la grabación: clasificación, rutas, detonaciones, oráculos, incidentes; en `observe`, lo que `enforce` habría hecho | 0 |
| `immune mode observe\|enforce` | Escribe `mode` en la configuración y lo cambia en el gateway en marcha | 0 |
| `immune autopatch off\|pr\|merge` | Escribe `autopatch`. El pipeline lo lee al empezar cada incidente | 0 |
| `immune rollback [--to RELEASE] [--keep-autopatch]` | Vuelve a poner en producción la release anterior (o `RELEASE`) por el mismo camino blue/green, con chequeo de salud y ventana de observación. Si `autopatch` es `merge`, lo deja en `pr`, salvo con `--keep-autopatch`. Reactiva las reglas de contención de los incidentes cuyo parche no está en esa release (un parche verificado levanta su regla) | 0; 1 si el despliegue no se completa |
| `immune init [--yes] [--no-llm] [--prod-db PATH] [--seed N]` | Genera `.immune/` para una aplicación. `--yes` sobrescribe un `.immune/` existente | 0 `READY`; 1 `NEEDS ATTENTION` |
| `immune doctor [--json] [--only 1,2]` | Ejecuta las comprobaciones de adaptación de un proyecto | 0 si todas pasan |
| `immune doctor --prereqs [--openemr] [--json]` | Comprueba los requisitos de la máquina; no necesita proyecto. `--openemr` incluye las imágenes fijadas de OpenEMR y MariaDB | 0 si no falta nada obligatorio |
| `immune deploy [--dry-run] [--experimental]` | Experimental; ver abajo | 2 sin `--experimental` |
| `immune anticipate list` | Lista los objetivos del modo de revisión de código fuente | 0 |
| `immune anticipate check T` | Chequeo mecánico de la versión vulnerable y de la oficial, sin modelo | — |
| `immune anticipate run T [--model M] [--out DIR]` | Revisión con modelo, chequeos, comparación y reporte | — |
| `immune anticipate recheck RESULT_DIR` | Reevalúa un resultado guardado, sin llamar al modelo | — |
| `immune fuxa [--runtime RUTA] <subcomando>` | Demo sobre FUXA v1.2.9, un camino aparte del stack ([fuxa.md](fuxa.md)). Subcomandos: `baseline [--repo]`, `up [--port]`, `watch [--input]`, `dashboard [--port]`, `reload-gateway`, `harden`, `validate-active`, `audit-coverage`, `patch-mode [auto\|review]`, `approve ID`, además de `status`, `demo` y `down` | — |

Un error de configuración termina con código 2 y un mensaje `immune: …`.

`immune deploy` es experimental. Sin `--experimental` imprime el comando de Compose que ejecutaría, lista lo que
no funciona y termina con código 2; `--dry-run` solo imprime el comando. Si `init` no generó un archivo de
Compose para el proyecto, el comando imprime los pasos manuales de `.immune/DEPLOY.md` y termina con código 0; si
no hay artefactos de despliegue, termina con código 1. El gateway que arranca no tiene pool de
clones ni bus de eventos: solo hace de proxy. El camino que funciona es `immune up`, que corre prod por su cuenta
desde los releases. Poner el gateway delante de un servicio que el cliente ya tiene en marcha no está construido.

`deploy/demo.sh up|reset|down|status` es un envoltorio de los mismos comandos para el demo incorporado.

### Comprobaciones de `immune doctor`

| N.º | Comprueba | Dónde corre |
|---|---|---|
| 1 | Configuración válida, el release se construye, la app arranca en un clon y responde la salud | contenedor sin red |
| 2 | El perfil crea una identidad que la app acepta | host |
| 3 | Los GET legítimos dan veredicto `clean` | host |
| 4 | Canarios sintéticos: una consulta concatenada, una apertura fuera de raíz y una respuesta con el marcador de otro dueño disparan cada oráculo | host |
| 5 | El clon L1 vuelve al estado de la semilla | host |
| 6 | Ningún valor privado real aparece en los datos sintéticos (por muestreo). Se omite cuando los datos vienen de `data.seed_command` y no hay `columns.yaml` | host |
| 7 | El comando de tests pasa en el runner | contenedor sin red |
| 8 | Los escenarios legítimos generados son deterministas | contenedor sin red |
| 9 | Imágenes de contenedor fijadas: las bases con digest del Dockerfile del proyecto, la imagen de la base de datos, `immune-base:1` e `immune-sidecar:1` existen en la máquina | host (`docker image inspect`) |

En un proyecto Python con SQLite el doctor ejecuta las comprobaciones 1 a 8. En un proyecto con
`app.runtime: generic` y `database.kind: mysql` ejecuta solo la 1 (en este caso: la configuración y el Dockerfile
existen) y la 9, e informa las demás como omitidas (`run` y `_mysql_checks` en `immune/doctor.py`).

## Modos

| Clave | Valores | Efecto |
|---|---|---|
| `mode` | `enforce` (por defecto) | El gateway desvía, captura y niega según la [tabla de decisión](arquitectura.md#33-detonación-y-decisión) |
| | `observe` | Clasifica y detona, pero toda respuesta sale de prod. Registra lo que `enforce` habría hecho |
| | `passthrough` | Solo por la API de administración del gateway (`POST /_admin/mode`), no por `immune mode`: clasifica y reenvía todo a prod sin detonar |
| `autopatch` | `merge` (por defecto del esquema; `immune init` escribe `pr`) | Merge y despliegue automáticos del parche que pasa las validaciones |
| | `pr` | Abre el pull request y se detiene; la regla sigue activa |
| | `off` | Solo regla |
| `repo.target` | `local` (por defecto) | Los pull requests son registros en un repositorio git bajo `<runtime>/repo` |
| | `github` | Pull requests con la CLI `gh` en `repo.github`. Verificado solo contra un `gh` simulado |

`autopatch` queda limitado a `pr` cuando el proyecto no tiene `tests.command`, y también cuando la validación
`legit` no tiene cobertura de la ruta parchada ([validaciones.md](validaciones.md)).

## Puertos

| Puerto por defecto | Clave en `ports:` | Proceso | Enlace |
|---|---|---|---|
| 8080 | `gateway` | gateway, tráfico de la aplicación | `127.0.0.1` |
| 8081 | `admin` | gateway, API de administración (`/_admin/*`, requiere `x-admin-token`) | `127.0.0.1` |
| 8090 | `dashboard` | dashboard y bus de eventos | `127.0.0.1` |
| 8070 | `fleet` | API de `fleet` (requiere `x-admin-token`) | `127.0.0.1` |
| 9000 | no configurable en `ports:` | gateway, ingesta de evidencia de los clones | no publicado; solo redes internas de Docker |

Los tres primeros los publica `deploy/compose.yaml` con el prefijo `127.0.0.1:`; el de `fleet` lo fija
`fleet/__main__.py`. Publicar el dashboard hacia otra interfaz es una decisión de quien opera la máquina (un
proxy inverso o un túnel); nada en el repositorio lo hace. El gateway no debe publicarse mientras proteja una
aplicación de demostración con defectos plantados.

## Secretos

Cada proyecto, incluido el demo, recibe cuatro secretos aleatorios en `<runtime>/secrets.env` (permisos 0600),
generados en el primer `up`, `reset` o `status` (`stack_secrets` en `immune/__main__.py`):

| Secreto | Uso |
|---|---|
| `PROD_APP_SECRET` | Secreto con el que la app de prod firma sus tokens (`auth.kind: immune-token`) |
| `SHADOW_APP_SECRET` | Secreto equivalente en los clones. Distinto del de prod |
| `ADMIN_TOKEN` | API de administración del gateway y API de `fleet` |
| `BUS_TOKEN` | Publicar eventos en el bus y leerlos sin tachar |

Una variable de entorno con el mismo nombre tiene prioridad sobre el archivo. Con `auth.kind: jwt-hs256` hay que
exportar además la variable indicada en `auth.secret_env`.

`deploy/demo.env` contiene valores de relleno sin valor real. Ningún stack levantado con `immune up` los usa.
Siguen siendo el valor de reserva cuando `python -m pipeline` o `python -m fleet` se ejecutan a mano sin esas
variables (`pipeline/config.py`, `fleet/config.py`); `fleet` no arranca sin `ADMIN_TOKEN` en su entorno. Un stack
levantado antes de que existiera `secrets.env` conserva los valores de `<runtime>/stack/containers.env`.

`<runtime>/stack/*.supervise.json` también contiene los secretos (permisos 0600).

## Variables de entorno

Variables que cambian el comportamiento de un stack. Se leen del entorno de `immune up`, que las hereda a los
procesos del host. Las variables internas de cada módulo están en su README.

| Variable | Efecto | Por defecto | Leída en |
|---|---|---|---|
| `IMMUNE_PROJECT` | Directorio del proyecto cuando no se pasa `--project` | sin definir | `immune/__main__.py` |
| `IMMUNE_NO_SYSTEMD` | Con cualquier valor, no usa systemd de usuario: procesos desacoplados | sin definir | `immune/__main__.py` |
| `NO_PIPELINE` | Con cualquier valor, `up` no arranca el pipeline | sin definir | `immune/__main__.py` |
| `POOL_SIZE` | Tamaño del pool de clones en un arranque desde `t0` | `pool_size` de la configuración | `immune/__main__.py` |
| `T0_REF` | Referencia git de la que se extrae `t0` en vez del árbol de trabajo | sin definir | `immune/__main__.py` |
| `CLAUDE_BIN` | Ruta de la CLI `claude` | `$CLAUDE_CODE_EXECPATH` si es ejecutable; si no, `claude` del `PATH` | `patcher/claude_cli.py` |
| `PATCHER_MODEL` | Modelo del generador de parches | `sonnet` | `patcher/claude_cli.py` |
| `PATCHER_TIMEOUT_S` | Tiempo máximo de una llamada al modelo, en segundos | 180 | `patcher/claude_cli.py` |
| `PATCHER_FORCE_FALLBACK=1` | Usa siempre el parche de respaldo | sin definir | `patcher/core.py` |
| `PATCHER_CLAUDE_CONFIG_DIR` | Directorio de configuración y login propio de la CLI del generador de parches (se le pasa como `CLAUDE_CONFIG_DIR`) | sin definir: el login de la máquina | `patcher/claude_cli.py` |
| `PATCHER_ANTHROPIC_API_KEY` | Clave de API propia del generador de parches (se le pasa como `ANTHROPIC_API_KEY`) | sin definir | `patcher/claude_cli.py` |
| `PIPELINE_MAX_ATTEMPTS` | Intentos de parche por incidente | 3 | `pipeline/config.py` |
| `PIPELINE_RULE_TTL_S` | TTL, en segundos, de la regla incorporada del pipeline. No afecta a la regla que deriva `patcher.derive_rule`, que no vence | sin definir o 0: la regla no vence | `pipeline/config.py` |
| `PIPELINE_REOPEN_COOLDOWN_S` | Espera, en segundos, antes de reabrir un incidente `escalated` ante evidencia nueva | 300 | `pipeline/config.py` |
| `PIPELINE_RETRY_COOLDOWN_S` | Espera base, en segundos, antes de reintentar un cierre transitorio | 60 | `pipeline/config.py` |
| `PIPELINE_MAX_RETRIES` | Reintentos de un cierre transitorio | 5 | `pipeline/config.py` |
| `POLICY_MAX_LINES`, `POLICY_MAX_FILES` | Tamaño máximo de un diff | 120, 4 | `pipeline/config.py` |
| `SMOKE_PATH` | Ruta del request de humo del despliegue; vacío lo omite | derivada del OpenAPI | `fleet/config.py` |
| `DEPLOY_WATCH_S` | Ventana de observación tras el cambio de upstream, en segundos | 20 | `fleet/config.py` |
| `DEPLOY_MIN_REQUESTS` | Requests mínimos para juzgar la tasa de 5xx | 20 | `fleet/config.py` |
| `CANARY_WEIGHT` | Fracción del tráfico de prod que va al release nuevo durante el canario de despliegue, entre 0 y 1. 0 lo desactiva | 0.2 | `fleet/config.py` |
| `CANARY_S` | Duración máxima del canario, en segundos. 0 lo desactiva | 8 | `fleet/config.py` |
| `CANARY_MIN_REQUESTS` | Requests mínimos en el lado canario para que el canario decida | 20 | `fleet/config.py` |
| `WAF_URL` | URL del WAF de detección. Vacía: no se consulta | vacía | `gateway/core.py` |
| `RECORD_MAX_MB` | Tamaño al que rota la grabación del gateway | 256 | `gateway/core.py` |
| `GW_CAPTIVE_TTL_S` | Vencimiento por inactividad de una sesión cautiva, en segundos | 900 | `gateway/core.py` |
| `DASHBOARD_SUBTITLE` | Subtítulo del panel | vacío | `dashboard/server.py` |
| `DASH_REDACT=0` | El dashboard no tacha los eventos para lectores sin token | tacha | `dashboard/server.py` |
| `DASH_EVENTS_LIMIT`, `DASH_EVENTS_LIMIT_MAX` | Eventos por página de `GET /events`, y máximo | 1000, 5000 | `dashboard/server.py` |
| `DASH_MAX_BODY_MB` | Cuerpo máximo de `POST /events` | 32 | `dashboard/server.py` |
| `DASH_MAX_EVENTS` | Eventos en memoria | 50000 | `dashboard/server.py` |
| `DASH_STORE_MAX_MB` | Tamaño al que rota el JSONL del bus; 0 lo desactiva | 256 | `dashboard/server.py` |

Las variables del gateway y del dashboard (`RECORD_MAX_MB`, `GW_CAPTIVE_TTL_S`, `WAF_URL`, `DASH_*`) se leen dentro
de sus contenedores. `deploy/compose.yaml` no las propaga desde el entorno de `immune up`: para cambiarlas hay que
agregarlas al bloque `environment` del servicio en ese archivo. `DASHBOARD_SUBTITLE` sí está en ese archivo, pero
su valor lo fija `compose_env` en `immune/__main__.py` (vacío, salvo para el proyecto de nombre `openemr`) y no se
toma del entorno de quien ejecuta `immune up`.

Variables que solo usan los laboratorios, que arrancan los procesos a mano:

| Variable | Efecto | Leída en |
|---|---|---|
| `PIPELINE_APP=external`, `REPRO_URL` | El pipeline reproduce contra el clon a través del sidecar en `REPRO_URL`, sin runner | `pipeline/__main__.py`, `pipeline/external.py` |
| `EXTERNAL_TARGET` | Archivo `target.yaml` de la etapa de parche para aplicaciones externas | `pipeline/__main__.py`, `pipeline/extfix.py` |
| `SIDECAR_CONFIG`, `SIDECAR_GRACE_MS`, `SIDECAR_CONTAINER`, `SQL_LOG_CMD`, `SQL_DIALECT`, `SQL_BASELINE`, `MARKERS_PATH`, `CLONE_ID`, `CLONE_KEY`, `COLLECTOR_URL`, `RELEASE` | Configuración del sidecar; las claves del archivo de configuración están en `sidecar/config.py` | `sidecar/config.py` |
| `PROD_CONTAINERS`, `BPF_IMAGE`, `PROD_GRACE_S` (15), `PROD_COOLDOWN_S` (30), `RECORD_PATH`, `REPRO_URL` | Vigilante de prod | `sidecar/prodwatch.py` |

## Archivos

### `.immune/` del proyecto

| Ruta | Contenido | Se versiona |
|---|---|---|
| `.immune/config.yaml` | Única fuente de datos propios de la aplicación. Esquema en [`contracts/product.md`](../contracts/product.md) | Sí |
| `.immune/openapi.yaml` | OpenAPI con las marcas `x-owner-scoped` y `x-sensitive` | Sí |
| `.immune/profile.py` | Perfil de la aplicación en los clones: identidad, raíces de archivos | Sí |
| `.immune/shadow/*.yaml` | Clasificación de columnas, autenticación, marcas, detección | Sí |
| `.immune/scenarios.py` | Escenarios legítimos generados por `init` | Sí |
| `.immune/report.md` | Qué detectó y qué supuso `init` | Opcional |
| `.immune/deploy/`, `.immune/DEPLOY.md` | Artefactos de `immune deploy` (experimental) | Opcional |
| `.immune/.gitignore` | Escrito por `init`: excluye `runtime/` y `deploy/immune.env` | Sí |
| `.immune/runtime/` | Estado del stack (tabla siguiente) | No |

El demo incorporado usa `runtime/` en la raíz del repositorio (clave `runtime_dir`).

### Directorio de runtime

| Ruta | Contenido |
|---|---|
| `run_id` | Identificador de la corrida actual |
| `secrets.env` | Los cuatro secretos |
| `releases/<id>/` | Releases: `t0` y uno por parche desplegado. Tras un despliegue se conservan `t0`, el activo, los montados por algún contenedor y los 5 más recientes |
| `data/prod/` | Base de datos de prod del demo incorporado. En otros proyectos, la ruta de `data.prod_db` |
| `data/shadow/`, `data/manifest.json`, `data/markers.json` | Semilla sintética, manifiesto y marcadores |
| `recordings/requests.jsonl` | Grabación de requests del gateway. Rota a `.1` |
| `bus/events.jsonl` | Registro de eventos del bus. Rota a `.1`; se conserva una generación. No se tacha |
| `pipeline/state.json` | Incidentes, cola y última posición leída del bus |
| `corpus/<clase>.jsonl` | Valores confirmados por clase; se conserva entre `reset` |
| `repo/` | Repositorio git de los pull requests locales |
| `stack/gateway-state.json` | Upstream, modo y reglas (con su vencimiento, si lo tienen). El canario de despliegue no se guarda |
| `stack/fleet-state.json` | Color activo, release, tamaño del pool |
| `stack/containers.env`, `stack/*.supervise.json` | Entorno de los contenedores y de los procesos supervisados |
| `logs/fleet.log`, `logs/pipeline.log` | Registros de los procesos del host; `reset` los vacía |
| `logs/*.pid`, `logs/*.pid.child` | Pid del supervisor y del proceso |
| `anticipate/` | Caché y reportes de `immune anticipate` |

`immune reset` borra `data`, `recordings`, `bus`, `releases` y `pipeline`. No borra una base de producción que no
puede regenerar: si el proyecto no tiene `data.seed_command` y `data.prod_db` está bajo `<runtime>/data`, esa base
se conserva (`seed` en `immune/__main__.py`).

## Despliegue y rollback

`fleet` despliega un release en el color libre (`_deploy`, `_canary` y `_watch` en `fleet/manager.py`):

1. Valida que el release existe. En el runtime genérico construye antes la imagen.
2. Arranca el contenedor del color libre y espera a que responda la salud.
3. Hace un request de humo: `SMOKE_PATH` si está definido; si no, el primer GET público y sin parámetros del
   OpenAPI que no sea la ruta de salud. Si no existe ninguno, el paso se omite y el resultado lo dice en `smoke`.
   En la tienda es `GET /api/products`; en `tareas-node` se omite.
4. Lee la tasa de 5xx del release que va a reemplazar.
5. Canario de despliegue: pide al gateway (`POST /_admin/canary`) que envíe la fracción `CANARY_WEIGHT` del
   tráfico de prod al release nuevo, sorteada por request, durante `CANARY_S` segundos como máximo. El gateway
   cuenta requests, 4xx y 5xx de cada lado.
6. Cambia el upstream del gateway, que drena los requests en curso. El cambio termina el canario.
7. Observa los contadores de prod durante `DEPLOY_WATCH_S`. Si el canario dio `ok`, el tiempo que duró se descuenta
   de la ventana, con un mínimo de 2 segundos.
8. Elimina el color anterior, reemplaza los clones libres y poda releases antiguos.

Una falla de salud o de humo detiene el despliegue antes del canario.

Veredicto del canario (campo `canary.verdict` del resultado y del evento `deploy.done`):

| Veredicto | Cuándo | Efecto |
|---|---|---|
| `worse` | Con al menos `CANARY_MIN_REQUESTS` requests en el lado canario: tiene algún 5xx y su tasa de 5xx supera `max(2 × la del release actual, la del release actual + 0.02)`; o tiene al menos 5 respuestas 4xx y su tasa de 4xx supera `max(2 × la del release actual, la del release actual + 0.10)`. Se evalúa durante la ventana, no al final | Se detiene el canario y el despliegue se aborta: el release nuevo nunca recibe todo el tráfico. `rolled_back` es `false` |
| `ok` | La ventana termina con al menos `CANARY_MIN_REQUESTS` requests en el lado canario y sin la condición anterior | Sigue el cambio de upstream |
| `skipped` | `CANARY_WEIGHT` o `CANARY_S` en 0; el gateway no acepta el canario o lo pierde; menos de `CANARY_MIN_REQUESTS` requests en el lado canario. Sin ningún request en ninguno de los dos lados, la espera se corta a los 2 segundos | Sigue el cambio de upstream, sin información del canario |

Un error de conexión con el release canario cuenta como un 5xx de ese lado y el request se reenvía al release
actual: el cliente no lo ve (`Gateway.to_prod`).

Durante la observación posterior al cambio, el despliegue se revierte si se cumplen las tres condiciones: al menos
`DEPLOY_MIN_REQUESTS` requests desde el cambio, al menos un 5xx, y una tasa de 5xx superior a
`max(2 × tasa anterior, tasa anterior + 0.02)`.

`traffic_validated` es `true` cuando hubo al menos `DEPLOY_MIN_REQUESTS` requests en la observación o cuando el
canario dio `ok`. En otro caso el despliegue queda aceptado con `traffic_validated: false` y un detalle que
empieza con "deployed; not validated by traffic".

Ni el canario ni el rollback detectan un comportamiento incorrecto que responde 200, ni nada que ocurra después de
la ventana.

## Tests

Los comandos se ejecutan desde la raíz del repositorio.

| Qué | Comando | Necesita |
|---|---|---|
| Suite completa sin modelo | `.venv/bin/pytest -q -m "not live"` | Docker |
| Sin los tests marcados `docker` | `.venv/bin/pytest -q -m "not live and not docker"` | Docker para algunos tests no marcados (los de `fleet/`) |
| Tests que llaman al modelo | `.venv/bin/pytest -q -m live` | CLI `claude` con sesión |
| Autotest de las validaciones | `.venv/bin/python -m pipeline.selftest` | Docker |
| Suite de `examples/notas` | `cd examples/notas && ../../.venv/bin/python -m pytest tests -q` | — |
| Análisis estático | `.venv/bin/python -m pyflakes $(git ls-files '*.py')` | `pyflakes` (incluido en `deploy/requirements.txt`) |

`pytest.ini` define los 12 directorios de `testpaths`, los marcadores `docker` y `live`, un tiempo máximo de 120
segundos por test, y suprime `DeprecationWarning`. No hay integración continua configurada. Los resultados de la
última ejecución están en [resultados.md](resultados.md#tests).

## Recuperación

El comportamiento ante fallas está especificado, con los tiempos medidos, en la sección 11 de
[`contracts/product.md`](../contracts/product.md). Resumen operativo:

| Situación | Qué pasa | Qué hacer |
|---|---|---|
| Muere `fleet` o `pipeline` | El supervisor lo reinicia, con espera de 1 s que se duplica hasta 30 s | Nada. Ver `logs/<nombre>.log` si se repite |
| Se cierra la terminal o la sesión SSH que ejecutó `immune up` | Los procesos siguen: corren como unidades de usuario de systemd, o desacoplados | Nada |
| Muere el gateway o el dashboard | Docker los reinicia (`restart: unless-stopped`); `fleet` los arranca si los encuentra detenidos. El gateway restaura upstream, modo y reglas desde `stack/gateway-state.json` | Nada |
| Se elimina el contenedor de prod o un clon | `fleet` lo recrea en su ciclo de reconciliación | Nada |
| El pipeline muere con un incidente abierto | Al volver, rehace el incidente desde el principio | Nada |
| El modelo no responde | El incidente queda contenido por la regla, se cierra como `rule_only` transitorio y se reintenta con espera creciente, hasta `PIPELINE_MAX_RETRIES` veces | Comprobar la sesión de `claude` |
| `immune status` informa `NOT HEALTHY` | — | `immune up`: repone lo que falta sin volver a `t0` |
| Reinicio de la máquina | Nada arranca solo | `immune up` retoma la corrida: mismo release, mismas reglas, incidentes abiertos |
| Estado inconsistente | — | `immune reset` vuelve a `t0` |

`immune up` nunca vuelve a `t0`. Retoma una corrida cuando `run_id` y `stack/fleet-state.json` coinciden y el
release registrado existe (`existing_run` en `immune/__main__.py`). En el runtime genérico solo la retoma mientras
sus contenedores existan, porque `immune down` elimina las imágenes de la aplicación.

## Carencias operativas conocidas

- Nada levanta el stack al iniciar la máquina.
- No hay integración continua.
- Sin `PATCHER_CLAUDE_CONFIG_DIR` ni `PATCHER_ANTHROPIC_API_KEY`, los procesos del host usan el login de Claude Code
  de la máquina y, por lo tanto, su cuota.
- `install.sh` solo está probado en Ubuntu 24.04 ARM64.
- El vigilante de prod y el WAF de detección no forman parte de `immune up`; solo los arrancan los laboratorios.
- Una regla no vence por defecto: la de un incidente sin parche queda activa hasta que se borra
  (`DELETE /_admin/rules/<id>` en la API de administración del gateway) o hasta `immune reset`.
- El Postgres de demostración del runtime genérico no está supervisado y no persiste datos entre `down` y `up`.

La lista completa de límites está en [limites.md](limites.md).
