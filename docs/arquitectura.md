# Arquitectura

Tipo de documento: explicación. Describe la arquitectura tal como está construida.
Los comandos, puertos y variables están en [operacion.md](operacion.md); los protocolos y esquemas, en
[`contracts/`](../contracts/README.md); las razones de cada decisión, en [decisiones.md](decisiones.md); los
límites, en [limites.md](limites.md).

Immune es un proxy inverso que se pone delante de una aplicación web. Cada request que considera sospechoso lo
ejecuta primero en una copia de la misma aplicación con datos sintéticos. Si ahí el ataque funciona, queda
confirmado por ejecución: el gateway contiene el punto vulnerable con una regla, y un pipeline propone un parche
de código, lo valida de forma mecánica y lo despliega.

## 1. Glosario

Estos términos se usan con el mismo significado en toda la documentación en español. Entre paréntesis, el término
de la documentación en inglés (`contracts/` y los README de cada módulo).

| Término | Significado |
|---|---|
| **prod** | La aplicación protegida, con sus datos reales. Corre desde un *release*. |
| **release** | Copia completa de las rutas `app.release_paths` del proyecto, en `<runtime>/releases/<id>/`. `t0` es el release inicial. Se monta de solo lectura en `/app`. |
| **clon** (*clone*) | Contenedor que corre el mismo release que prod, con una base de datos sintética (la *semilla sombra*) y con los oráculos activos. |
| **oráculo** (*oracle*) | Comprobación mecánica, de sí o no, sobre lo que la aplicación hizo al atender un request dentro de un clon. Hay cinco: `sql`, `file`, `proc`, `net`, `owner`. |
| **detonación** (*detonation*) | Ejecutar un request sospechoso en un clon antes de decidir si llega a prod. |
| **veredicto** (*verdict*) | Resultado de una detonación: `clean`, `oracle` o `inconclusive`. |
| **L0** | Respuestas falsas y deterministas del propio gateway para una lista fija de rutas de escáner. |
| **L1** | Clon compartido de detonación. Atiende un request y vuelve al estado de la semilla. |
| **L2** / **cautivo** (*captive*) | Sesión que disparó un oráculo y desde entonces es atendida solo por un clon dedicado, nunca por prod. |
| **marcador** (*marker*) | Cadena `MK` + 10 caracteres, distinta por dueño, incrustada en cada dato privado sintético. |
| **manifiesto** (*manifest*) | `manifest.json`: mayor uid de la semilla (`seed_max_uid`), dueño de cada objeto, ids canario. |
| **canario de despliegue** (*canary*) | Fracción del tráfico de prod que el gateway envía al release nuevo antes del cambio de upstream. No tiene relación con los ids canario del manifiesto. |
| **incidente** (*incident*) | Unidad de trabajo del pipeline: un oráculo disparado en una ruta y un parámetro. |
| **PoC** | Estado previo del clon más los requests que reproducen el incidente. |
| **regla** (*rule*) | Entrada del gateway que marca un punto confirmado como vulnerable: método + ruta, con un alcance (`param`, `param_present` o `all`), una gramática y, opcionalmente, una identidad (`untrusted`) y un TTL. Por defecto no vence: dura hasta que se borra. |
| **validación** (*gate*) | Cada una de las cinco comprobaciones mecánicas que un parche debe pasar: `policy`, `properties`, `poc`, `tests`, `legit`. |
| **runner** | Contenedor sin red donde se ejecuta código de la aplicación durante la reproducción y las validaciones. |
| **bus** | Registro de eventos (HTTP + JSONL) que sirve el dashboard. |
| **identidad confiable** | Usuario con `uid <= seed_max_uid`. Cualquier otro, o un anónimo, es no confiable. |

## 2. Componentes y dónde corre cada uno

```mermaid
flowchart LR
  C[Cliente] -->|127.0.0.1:8080| GW
  subgraph Contenedores["Contenedores (docker compose, proyecto immune-NOMBRE)"]
    GW[gateway<br/>datos 8080, admin 8081,<br/>ingesta de evidencia 9000]
    DASH[dashboard<br/>bus de eventos, 8090]
  end
  subgraph Fleet["Contenedores creados por fleet"]
    PROD[prod blue / green<br/>red prodnet]
    CL[clones L1 / L2<br/>red clonenet]
  end
  subgraph Host["Procesos del host (unidades systemd de usuario)"]
    FL[fleet<br/>127.0.0.1:8070]
    PL[pipeline<br/>+ patcher como librería]
    LLM[CLI claude<br/>confinada]
  end
  RUN[runner<br/>contenedor sin red]
  GW --> PROD
  GW --> CL
  CL -->|evidencia firmada| GW
  GW -->|eventos| DASH
  FL -->|eventos| DASH
  PL -->|eventos| DASH
  DASH -->|oracle.fired| PL
  PL -->|reglas| GW
  PL -->|deploy| FL
  FL -->|pool y upstream| GW
  PL --> RUN
  PL --> LLM
```

| Componente | Directorio | Corre como | Función |
|---|---|---|---|
| Gateway | `gateway/` | contenedor `immune-<proyecto>-gateway`; puertos 8080 (datos) y 8081 (admin) publicados en `127.0.0.1`; puerto 9000 solo en las redes internas | Clasifica, detona, decide la ruta de cada request, aplica las reglas, graba los requests |
| Instrumentación en proceso | `shadow/` | dentro de cada clon de una app Python ASGI | Oráculos y veredicto |
| Observador externo | `sidecar/` | `python -m sidecar`: contenedor junto a cada clon de una app con `app.runtime: generic` (modo `attach`); proceso del host en los laboratorios (modo `docker`) | Oráculos desde fuera del proceso: `strace`, proxy del protocolo de Postgres o de MySQL, registro de sentencias de la base, traza de PHP |
| Vigilante de prod | `sidecar/prodwatch.py` | proceso del host; solo lo arranca el laboratorio de Grafana | Las reglas `file`, `proc` y `net` sobre contenedores de prod con `bpftrace`; solo alerta (`prod.alert`) |
| WAF de detección | `waf/`, `gateway/waf.py` | contenedor `immune-waf:1`; opcional en `immune up` (`IMMUNE_WAF=1`) y usado por el laboratorio de ScadaBR. El gateway lo consulta si tiene `WAF_URL` | OWASP CRS sobre Coraza: marca como sospechoso un request que el clasificador dio por limpio. No bloquea |
| Fleet | `fleet/` | proceso del host, `127.0.0.1:8070` | Crea y destruye los contenedores de prod y de los clones; despliegue blue/green |
| Pipeline | `pipeline/` | proceso del host | Ciclo de vida del incidente, runner, las cinco validaciones, auditoría de clase |
| Patcher | `patcher/` | librería cargada por el pipeline | Arma el prompt, llama a la CLI `claude` confinada, deriva la regla y las variantes del PoC, parches de respaldo |
| Dashboard | `dashboard/` | contenedor `immune-<proyecto>-dashboard`; puerto 8090 publicado en `127.0.0.1` | Bus de eventos y panel en vivo |
| CLI | `immune/` | comando del host | `init`, `up`, `down`, `reset`, `status`, `report`, `mode`, `autopatch`, `doctor`, `deploy`, `anticipate`, `fuxa` |
| Código compartido | `immune_contracts/` | librería | Token de autenticación, gramática, headers internos, tipos de evento |

Los cuatro puertos por defecto (8080, 8081, 8090, 8070) se cambian en la clave `ports` de `.immune/config.yaml`.
`deploy/compose.yaml` publica los tres primeros solo en `127.0.0.1`, y `fleet/__main__.py` enlaza el suyo a
`127.0.0.1`.

Redes de Docker (definidas en `deploy/compose.yaml`): `prodnet`, `clonenet` y `ctrlnet` son `internal`, sin salida
a internet. El gateway está en las tres y en `edge`, la única red con puerto publicado. Los contenedores de prod
solo están en `prodnet` y los clones solo en `clonenet`: un clon no comparte red con prod ni con el dashboard. Lo
único que alcanza es el gateway.

`fleet` y `pipeline` corren bajo `immune.supervise`, que los reinicia si mueren. Con un gestor systemd de usuario
son las unidades transitorias `immune-<proyecto>-fleet` e `immune-<proyecto>-pipeline`; sin él, procesos
desacoplados de la terminal (`start_host` en `immune/__main__.py`).

El resto del repositorio no forma parte del camino de un request de un stack levantado con `immune up`:

| Directorio | Contenido |
|---|---|
| `victim/`, `examples/notas/`, `examples/tareas-node/` | Aplicaciones de demostración con defectos plantados por el equipo |
| `examples/openemr/` | Perfil escrito a mano para OpenEMR 8.2.0 sin modificar (PHP + MariaDB, runtime genérico). Guía: [openemr.md](openemr.md) |
| `labs/grafana-cve-2021-43798/`, `labs/scadabr-cve-2026-8602/` | Laboratorios guionados sobre software de terceros. No usan `immune up` ni `fleet`: un script levanta gateway, sidecar, bus y pipeline como procesos del host (sección 5.1) |
| `immune/fuxa.py`, `immune/fuxa_dashboard.py`, `immune/fuxa_rules.py`, `immune/fuxa_runtime/`, `fleet/fuxa.py` | Demo sobre FUXA v1.2.9 (`immune fuxa …`). Es un camino aparte: tiene su propio gateway en Node (`immune/fuxa_runtime/gateway.cjs`), su propio dashboard y controles dentro del servidor; no usa el gateway, los clones ni el pipeline descritos aquí. Guía: [fuxa.md](fuxa.md) |
| `sim/` | Tráfico legítimo de la tienda (`sim/legit.py`), escenarios guionados (`sim/scenarios.py`) y atacante de demostración (`sim/attacker.py`) |
| `anticipate/` | Modo de revisión de código fuente |
| `waf/` | Fuente en Go e imagen del WAF de detección |
| `landing/` | Página estática de presentación |
| `deploy/` | Dockerfiles, archivo de Compose y dependencias fijadas |
| `acceptance/` | Tests de aceptación de la tienda, la instrumentación y el gateway |

Cada módulo, laboratorio y ejemplo tiene su README.

## 3. Camino de un request por el gateway

El código está en `gateway/core.py` (`Gateway.handle` y `Gateway._detonation`) y `gateway/classifier.py`
(`classify`).

```mermaid
flowchart TD
  R[Request] --> RD{Legible y dentro<br/>de los límites}
  RD -->|no| E4[400 / 408 / 413<br/>responde el gateway]
  RD -->|sí| CAP{Sesión cautiva<br/>y no confiable}
  CAP -->|sí| L2[Clon L2 de la sesión]
  CAP -->|no| SC{Ruta de escáner que<br/>la app no define}
  SC -->|sí| L0[Respuesta L0]
  SC -->|no| CL{classify}
  CL -->|limpio| WAF{WAF configurado<br/>y marca anomalía}
  WAF -->|no| PROD[prod]
  WAF -->|sí| DET
  CL -->|evidencia directa| EV{Identidad confiable}
  EV -->|sí| DENY[404 genérico]
  EV -->|no| L2
  CL -->|sospechoso| DET[Detonación en un clon L1]
  DET -->|sin clon libre en 0.3 s| NC{Regla, traversal<br/>o señal fuerte}
  NC -->|sí| DENY
  NC -->|no| PROD
  DET -->|veredicto oracle| OR{Identidad confiable}
  OR -->|sí| DENY
  OR -->|no| SH[Responde el clon;<br/>la sesión queda cautiva]
  DET -->|veredicto clean| TR{Segmento .. en la ruta}
  TR -->|sí| DENY
  TR -->|no| PROD
  DET -->|veredicto inconclusive| RU{Regla en modo estricto o<br/>segmento .. en la ruta}
  RU -->|sí| DENY
  RU -->|no| PROD
```

### 3.1 Lectura

`Gateway._read` rechaza sin reenviar: un destino que no empieza por `/` (400), un cuerpo de más de 10 MiB (413) y
un cuerpo que no termina en 30 segundos (408). Si el cliente se desconecta a mitad del cuerpo, el request se
descarta: no se reenvía, no se responde y no se registra. Los headers entrantes con el prefijo interno
(`wire.INTERNAL_PREFIX`) se eliminan, de modo que un cliente no puede hacerse pasar por el gateway ante un clon.

La sesión es `uid:<n>` si el request trae una identidad válida, y `gwsid:<valor>` en otro caso. `gwsid` es una
cookie que el gateway emite cuando falta. La cookie se quita del header `Cookie` que se reenvía a prod y a los
clones (`_out_headers`).

### 3.2 Clasificación

`classify` devuelve una de tres clases, a partir del request, del OpenAPI del proyecto, del manifiesto y de las
reglas activas. No usa historial, IP ni user-agent, salvo el contador de enumeración por sesión.

| Clase | Motivos (`reasons`) |
|---|---|
| Evidencia directa | `honeytoken`: llega desde fuera un token firmado con el secreto de los clones (`immune/auth.py`). `canary:<param>`: un parámetro de ruta apunta a un id canario del manifiesto y quien pide no es su dueño ni administrador. |
| Sospechoso | `grammar:*` o `schema:*`: un valor se sale de la gramática segura o del esquema del OpenAPI. `dup_query:<k>`: parámetro de consulta duplicado. `traversal:path` y `traversal:query.<k>`: segmentos `..` (regla incorporada, también en rutas fuera del OpenAPI). `path:encoded_slash`: las dos lecturas de la ruta enrutan distinto. `owner_scoped:anonymous` y `owner_scoped:untrusted`: ruta marcada `x-owner-scoped` con identidad no confiable. `owner_scoped:mismatch:<param>`: identidad de la semilla, no administradora, que pide un objeto que el manifiesto atribuye a otro. `enumeration`: más de 8 ids distintos en rutas de dueño desde una sesión en 30 segundos. `rule:<id>`: coincide con una regla activa (sección 3.3). `waf:<id>`: el WAF de detección marcó una anomalía en un request que `classify` dio por limpio (sección 3.7). `scanner`: ruta de la lista L0 que la aplicación no define; la responde el propio gateway. |
| Limpio | Ningún motivo. |

Rutas: el gateway compara rutas y reglas contra dos lecturas del destino, la que decodifica una vez y luego separa
por `/` (como uvicorn y starlette) y la que separa y luego decodifica. Una regla aplica si coincide con cualquiera
de las dos. `%252F` y `%5C` nunca cuentan como separadores.

Los campos marcados `x-sensitive` no se inspeccionan y se tachan en la grabación. Las rutas que no están en el
OpenAPI se clasifican como limpias, salvo que coincidan con una regla, con la regla incorporada de traversal o con
la lista L0, o que traigan un parámetro de consulta duplicado o un honeytoken.

### 3.3 Detonación y decisión

Un request sospechoso se ejecuta en un clon L1 libre con los mismos bytes que recibiría prod. El clon responde con
un header de veredicto; si falta, el veredicto es `inconclusive`. Después de cada request el clon L1 vuelve al
estado de la semilla. La decisión está en un solo lugar, `Gateway._detonation`:

| Resultado de la detonación | Identidad no confiable | Identidad confiable |
|---|---|---|
| `oracle` | Recibe la respuesta del clon (datos sintéticos); la sesión queda cautiva | 404 genérico: nunca se le sirven datos sintéticos |
| `clean` | prod, salvo `traversal:path`, que recibe 404 | igual |
| `inconclusive` (401, 404 o 5xx en el clon, o sin confirmación) | 404 si trae `traversal:path` o si coincide con una regla en modo estricto; si no, prod | igual |
| Sin clon libre en 0.3 s | 404 si coincide con cualquier regla activa, trae `traversal:path` o tiene señal fuerte (`schema:`, `grammar:`, `dup_query:`, `traversal:`); si no, prod | igual |

Una excepción dentro del manejo del request también termina en 404 genérico (`Gateway.data_app`).

Cuándo coincide una regla y cuándo lo hace en modo estricto (`classify` y `_rule_hit` en `gateway/classifier.py`;
el esquema es `contracts/schemas/rule.schema.json`):

| Alcance (`scope`) | El request coincide con la regla cuando | Coincidencia estricta (`rule_strict`) |
|---|---|---|
| `all` | usa el método y la ruta de la regla | siempre |
| `param` | trae el parámetro con un valor fuera de la gramática | siempre |
| `param_present` | trae el parámetro, con cualquier valor | solo si el valor está fuera de la gramática |

Una regla con `identity: untrusted` no se aplica a una identidad confiable; sin ese campo se aplica a todas. La
usan los incidentes de falta de autenticación: el oráculo `owner` disparado por un request anónimo
(`pipeline/rules.py`). El parámetro de una regla puede estar en `query`, `path`, `json`, `form` o `header`.

Consecuencias que conviene tener presentes:

- Un falso positivo del clasificador cuesta la latencia de una detonación; el cliente recibe la respuesta real de
  prod.
- Sin regla activa, un veredicto `inconclusive` falla abierto: el request llega a prod.
- Una regla fuerza la detonación. Si el clon dice `clean`, el request pasa a prod: una regla es tan fuerte como el
  oráculo.
- Con `param_present`, todo request que trae el parámetro se detona, también el legítimo. Un valor dentro de la
  gramática con veredicto `inconclusive` pasa a prod; la razón es que un clon tiene credenciales sintéticas y un
  login real da 401 ahí. Ese mismo valor recibe 404 cuando no hay clon libre, porque la decisión sin clon mira
  cualquier coincidencia y no solo las estrictas.
- Los clones corren la semilla. Un objeto creado en prod después de la semilla no existe en el clon y da 404 allí.

### 3.4 Sesiones cautivas

Una sesión cautiva se atiende desde un clon L2 que se asigna en su siguiente request (`Gateway.captive`). Hay un
tope global de sesiones (`max_sessions` en `gateway/pool.py`), desalojo de la más antigua cuando falta un clon y
vencimiento por inactividad a los 900 s. Una identidad confiable nunca queda cautiva. No hay tope por origen.

### 3.5 Modo `observe`

`Gateway.observe` clasifica y detona igual que `enforce`, pero toda respuesta sale de prod: nada se niega, se
desvía ni se captura. Cada evento registra en `would_route` la decisión que `enforce` habría tomado.
`immune report` las resume. El WAF de detección no se consulta en este modo.

El gateway acepta un tercer modo, `passthrough` (`POST /_admin/mode`): clasifica, publica el evento y reenvía todo a
prod sin detonar. `immune mode` solo ofrece `observe` y `enforce`.

### 3.6 Segunda comprobación opcional (`aftercheck`)

Con `aftercheck: true` (desactivado por defecto), un request clasificado como limpio y ya respondido por prod se
repite después en un clon L1. Si un oráculo dispara, se abre el incidente como en cualquier detonación. La primera
respuesta no se detiene. El detalle está en [`contracts/product.md`](../contracts/product.md).

### 3.7 WAF de detección (opcional)

Si el gateway tiene `WAF_URL`, `Gateway._waf_upgrade` envía cada request que `classify` dio por limpio, en modo
`enforce`, a un servicio que lo evalúa con OWASP Core Rule Set sobre Coraza (`waf/main.go`, `POST /eval`). Si el
servicio informa una anomalía, el request pasa a sospechoso con el motivo `waf:<id de regla>` y se detona como
cualquier otro. El WAF no bloquea ni responde al cliente. Un error, un timeout (1.5 s) o una respuesta distinta de
200 dejan el request como limpio (`gateway/waf.py`).

Estado: `immune up` lo arranca solo con `IMMUNE_WAF=1` en su entorno (perfil `waf` de `deploy/compose.yaml`; la imagen `immune-waf:1` se construye en el primer uso). Sin esa variable, el stack no lo usa. Verificado el 2026-11-22: la configuración de Compose, y la imagen corriendo con las mismas restricciones del servicio (solo lectura, sin capacidades), que marca una inyección SQL y deja pasar una búsqueda normal a través de `gateway/waf.py`. No se levantó un stack completo con el WAF. También lo arranca `labs/scadabr-cve-2026-8602/lab.sh`. Los tests (`gateway/tests/test_waf.py`) cubren el cliente y
el cambio de clase con un servicio simulado; no hay un test que ejecute Coraza.

## 4. Oráculos

| Oráculo | App Python ASGI (`shadow/`) | Runtime genérico (`sidecar/`) |
|---|---|---|
| `sql` | Comprobación por tokens (`shadow/sqltaint.py`) sobre las sentencias ejecutadas con `sqlite3`: un valor de entrada que abarca más de un token | La misma comprobación sobre el texto de las sentencias que ve el proxy de Postgres (`sidecar/pgproxy.py`) o el de MySQL y MariaDB (`sidecar/mysqlproxy.py`), o sobre el registro de sentencias de la base del clon (`sql_log`, `sidecar/sqllog.py`). Con `sql_log` hay además una regla de estructura: una sentencia cuya huella no está en la línea base aprendida dispara (`reason: new_structure`) |
| `file` | `sys.addaudithook` con una lista de permitidos aprendida en el precalentamiento (`shadow/instrument.py`): apertura fuera de las raíces permitidas | `strace` sobre los procesos de la app: `openat`, `openat2`, `open`, `creat`. Con `protected_paths`, solo aperturas (también las fallidas) de rutas protegidas, y un marcador de archivo visto en la respuesta |
| `proc` | El mismo hook: proceso hijo | `execve`, `execveat`, `fork`, `vfork`, `clone`, `clone3` |
| `net` | El mismo hook: conexión saliente | `connect`, `sendto`, `sendmsg` |
| `owner` | La respuesta contiene el marcador de otro dueño | Igual, en el cuerpo de la respuesta |

Los oráculos corren solo en los clones, nunca en el proceso de prod. Lo que cada uno no ve está en
[limites.md](limites.md) y en `shadow/README.md` y `sidecar/README.md`.

Piezas del runtime genérico (`sidecar/config.py` enumera las claves de configuración):

- **Ubicación del sidecar** (`mode`): `attach`, un contenedor que comparte los espacios de PID y de red del clon
  (lo que usan `fleet` y el pipeline); `launch`, el sidecar arranca la app como proceso hijo trazado; `docker`, el
  sidecar corre fuera y un contenedor trazador (`immune-strace:1`) se une al espacio de PID del contenedor de la
  app (lo usa el laboratorio de Grafana).
- **Línea base de SQL** (`python -m sidecar.learn`): repite por el sidecar, firmados con la clave del clon, los
  requests que el gateway grabó como limpios, para aprender la estructura de las sentencias legítimas. La regla de
  estructura está apagada hasta que se aprende al menos un request.
- **Pila de PHP** (`shadow.tracer.kind: php-xdebug`, `sidecar/phptrace.py`): los clones corren una imagen
  `<imagen>-trace` con Xdebug en modo traza y cada evento de oráculo recibe la pila de la aplicación. Prod no corre
  esa imagen. Sin trazador, la evidencia del runtime genérico no trae pila.
- **Oráculos del perfil**: si el perfil define `extra_oracles`, el sidecar lo llama después de los oráculos base
  (`sidecar/server.py`). Lo usa el perfil de OpenEMR.
- **`sidecar/httpds`** (`python -m sidecar.httpds`): proxy aparte, de un solo oráculo, para el laboratorio de
  ScadaBR. Dispara cuando una escritura en `/ScadaBR/httpds` fue consumida por un punto de datos.

### 4.1 Vigilante de prod (solo alerta)

`python -m sidecar.prodwatch` aplica las reglas `file`, `proc` y `net` del sidecar a contenedores de prod. Usa
`bpftrace` filtrado por el cgroup del contenedor (`openat`, `execve`, `connect`), en un contenedor trazador
`--privileged` sin red. No bloquea ni detiene el proceso. Ante un evento busca en la grabación del gateway los
requests enviados a prod alrededor de ese instante, los repite en el clon a través del sidecar y publica
`prod.alert` en el bus; si una repetición dispara en el clon, el sidecar envía la evidencia y el pipeline abre el
incidente como en una detonación. Es detección posterior: el request ya se ejecutó en prod.

Estado: `immune up` no lo arranca. Solo lo usa `labs/grafana-cve-2021-43798/lab.sh`. Los tests
(`sidecar/tests/test_prodwatch.py`) cubren las reglas y la selección de candidatos sin `bpftrace`.

## 5. Ciclo de vida de un incidente

El código está en `pipeline/orchestrator.py` (`Pipeline._flow`). El pipeline procesa un incidente a la vez; los
demás esperan en una cola persistente. La clave de deduplicación es tipo de oráculo + método + plantilla de ruta +
parámetro.

```mermaid
sequenceDiagram
  participant GW as gateway
  participant BUS as bus (dashboard)
  participant PL as pipeline
  participant RUN as runner
  participant LLM as CLI claude
  participant FL as fleet
  GW->>BUS: oracle.fired
  BUS->>PL: evento
  PL->>BUS: incident.opened
  PL->>RUN: PoC x3 + variantes, release actual
  PL->>BUS: poc.ready
  PL->>GW: POST regla
  GW->>BUS: rule.active
  loop hasta 3 intentos
    PL->>LLM: prompt (evidencia como dato)
    LLM-->>PL: diff
    PL->>BUS: patch.attempt, patch.diff
    PL->>RUN: validaciones policy, properties, poc, tests, legit
    PL->>BUS: gate.result (una por validación), pr.opened al pasar policy
  end
  PL->>BUS: pr.merged
  PL->>FL: POST /deploy
  FL->>GW: canario (opcional) y cambio de upstream
  FL->>BUS: deploy.started, deploy.done
  PL->>GW: DELETE regla
  PL->>RUN: PoC + variantes, release desplegado
  PL->>GW: el mismo request, sesión nueva
  PL->>BUS: verify.result, incident.closed
```

1. **Reproducción.** El PoC se ejecuta tres veces en el runner sobre el release actual. Las tres deben disparar el
   tipo de oráculo del incidente y, cuando el incidente tiene archivo de origen, con ese archivo en la pila. Si no
   se cumple 3 de 3, el pipeline publica igualmente la regla incorporada (`Pipeline.escalate`) y cierra el
   incidente como `rule_only` con `outcome_detail: escalated`: queda contenido, sin parche automático, a la espera
   de una persona. Evidencia nueva para la misma clave lo reabre pasado `PIPELINE_REOPEN_COOLDOWN_S`.
2. **Regla.** `patcher.derive_rule` propone la regla y `pipeline/rules.py` (`finalize`) la valida contra su
   esquema; si no valida, usa la regla incorporada (`default_rule`). El pipeline la publica en el gateway. Para
   `sqli` y `traversal` con parámetro direccionable el alcance es `param_present`: todo request que trae el
   parámetro se detona, y la gramática solo decide el caso `inconclusive`. Para `idor`, sin parámetro, o con un
   parámetro `x-sensitive`, el alcance es `all`: toda la ruta. Si el oráculo `owner` disparó para un request
   anónimo, la regla `all` lleva `identity: untrusted`. La regla no tiene TTL por defecto: dura hasta que el parche
   queda verificado o alguien la borra. Mientras el incidente siga cerrado sin parche, el pipeline la repone si el
   gateway la pierde (`Pipeline.keep_rules`).
3. **Parche.** Si `autopatch` es `off`, el incidente se cierra como `rule_only`. Si no, `patcher.propose` devuelve
   un diff, hasta `PIPELINE_MAX_ATTEMPTS` veces (3 por defecto); el detalle de la validación que rechazó un intento
   se entrega al siguiente.
4. **Validaciones.** Las cinco de [validaciones.md](validaciones.md), en orden, deteniéndose en la primera que
   falla. El pull request se abre cuando pasa `policy`.
5. **Merge y release.** Con `autopatch: merge` y sin topes, el pipeline hace merge y materializa el release
   `<sha[:12]>`. Con `autopatch: pr`, o si una validación fue omitida o quedó sin cobertura, el incidente se
   cierra como `rule_only` con el PR abierto y la regla activa.
6. **Despliegue.** `fleet` arranca el color libre, espera la salud, hace un request de humo, corre el canario de
   despliegue, cambia el upstream del gateway, observa la tasa de 5xx y revierte si empeora (`_deploy`, `_canary` y
   `_watch` en `fleet/manager.py`). La secuencia y los umbrales están en
   [operacion.md](operacion.md#despliegue-y-rollback).
7. **Verificación.** El pipeline quita la regla y comprueba dos cosas: en el runner, el PoC y sus variantes no
   disparan ningún oráculo sobre el release desplegado; por el gateway, el mismo request desde una sesión nueva es
   reenviado a prod (el registro `prodlog` del gateway debe confirmar `forwarded: true`). Si alguna falla, la
   regla se vuelve a publicar y el incidente se cierra como `rule_only`.
8. **Auditoría de clase.** Tras cerrar un incidente como `patched` o `rule_only` (salvo `escalated`), `pipeline/audit.py` deriva del
   OpenAPI, por forma del esquema, los demás pares operación y parámetro que la misma clase podría afectar, y los
   prueba en el runner. Cada oráculo que dispara abre un incidente con origen `audit`, que sigue el mismo flujo.
   Hay una auditoría por clase y por release. Está activa por defecto solo para `python-asgi`.

Resultados posibles de un incidente:

| `outcome` | Significado |
|---|---|
| `patched` | Release desplegado y verificado |
| `rule_only` | Se publicó una regla y sigue activa; no hay parche desplegado. `outcome_detail` dice por qué cuando hay una causa con nombre: `escalated` (el PoC no reprodujo 3 de 3), `autopatch_off`, `pr_open`, `transient` (se reintenta) |
| `error` | El flujo falló antes de publicar una regla; se reintenta como un cierre transitorio |

El valor `not_reproducible` sigue en el esquema del evento `incident.closed` (`immune_contracts/events.py`), pero
ningún camino del pipeline lo produce ya: un PoC que no reproduce 3 de 3 termina en `rule_only` / `escalated`.

### 5.1 Aplicaciones externas (laboratorios)

Con `PIPELINE_APP=external` y `REPRO_URL`, el pipeline (`pipeline/external.py`) no usa el runner: reproduce el
incidente repitiendo el request contra el clon a través del sidecar y publica la regla incorporada. Si además
`EXTERNAL_TARGET` apunta a un archivo `target.yaml`, sigue una etapa de parche propia (`pipeline/extfix.py`):

1. El modelo, con la misma CLI confinada, lee un árbol de trabajo del repositorio de la aplicación y edita solo
   archivos que no son de test bajo `source_dirs`.
2. Cinco validaciones, distintas de las de la sección 5: `policy` (zona permitida, tamaño), `build` y `tests` en
   un contenedor `--network none` con la imagen de `sandbox.image`, `poc` (la aplicación candidata, trazada con
   los oráculos del sidecar, no dispara con el request original ni con sus variantes) y `legit` (las rutas
   declaradas responden igual que en el release actual).
3. Rama, merge en un clon local del repositorio, despliegue blue/green con observación de 5xx y verificación del
   request original contra prod.

Este camino solo lo usa el laboratorio de Grafana. No pasa por `fleet`, y no tiene canario de despliegue ni
auditoría de clase. El laboratorio de ScadaBR usa `pipeline/external.py` hasta la regla y, para el parche, sus
propios scripts (`labs/scadabr-cve-2026-8602/README.md`).

## 6. Fronteras de confianza

### Qué puede leer y escribir el modelo

- El modelo se invoca como proceso del host: `claude -p` con `--tools Read,Edit`, `--strict-mcp-config`,
  `--disable-slash-commands`, `--restricted`, `--permission-mode dontAsk` y `--permission-prompts none`
  (`patcher/claude_cli.py`, `command`). No tiene herramienta de shell ni de red.
- Lee una copia temporal de las rutas `app.release_paths` del release (`patcher/workspace.py`). El directorio git
  de esa copia vive fuera del árbol de trabajo.
- Puede editar solo una lista de archivos: los de la pila del incidente que están bajo `app.source_dirs`
  (`editable_files` en `patcher/core.py`). En el runtime genérico, los archivos de la pila de PHP cuando hay
  trazador y, si no, los que el pipeline elige a partir de la ruta, el parámetro y lo observado
  (`pipeline/generic_patch.py`). Un incidente puede traer la lista de forma explícita; solo lo hace el script del
  laboratorio de ScadaBR. `Write` y la edición de directorios `tests` están denegadas.
- Su única salida aceptada es el diff de esa copia. No decide nada: deciden las validaciones.
- La evidencia y el detalle de las validaciones anteriores van en el prompt entre marcas con un nonce, declaradas
  como dato no confiable. Los headers `authorization`, `cookie` y `x-imm-signature` se tachan.
- El confinamiento lo aplica la propia CLI con esas opciones. No hay un sandbox del sistema operativo alrededor
  del proceso `claude`, que corre con el usuario de quien ejecutó `immune up` y, salvo que se configure una
  identidad propia (`PATCHER_CLAUDE_CONFIG_DIR` o `PATCHER_ANTHROPIC_API_KEY`), con su login de Claude Code. No
  hereda el entorno del pipeline: recibe una lista permitida de variables, sin los secretos del stack
  (`child_env` en `patcher/claude_cli.py`). El
  contenido del prompt (código de la aplicación y request del atacante) sale hacia el proveedor del modelo.

El texto del atacante es dato, nunca instrucción. La defensa contra un parche dirigido por ese texto es el
confinamiento de herramientas más las validaciones, y la validación `policy` es heurística
([validaciones.md](validaciones.md)).

En la etapa de parche de aplicaciones externas (sección 5.1) el modelo lee el repositorio completo de la
aplicación y la lista de archivos editables sale de `source_dirs` del archivo `target.yaml`, no de una pila.

### Dónde se ejecuta código de la aplicación

| Lugar | Aislamiento |
|---|---|
| prod y clones (`fleet/manager.py`, `_create`) | Contenedor con sistema de archivos de solo lectura, `cap_drop ALL`, `no-new-privileges`, límites de pids y memoria, red interna |
| runner (`pipeline/runner.py`) | `docker run --network none --read-only`, capacidades eliminadas, límites de pids, memoria y CPU; `runtime/` y `.git` ocultos |
| `immune init` y `immune doctor` | Las comprobaciones 1, 7 y 8 del doctor corren en contenedores `--network none`. El volcado del OpenAPI (`dump` en `immune/initsteps/openapi.py`) se intenta primero en un contenedor `--network none`; si Docker o la imagen `immune-base:1` no están disponibles, o si ese intento no devuelve el documento, se repite en un subproceso del host. La validación del perfil y las comprobaciones 2 a 5 corren siempre en el host, como el usuario que invoca (`immune/initsteps/hostrun.py`). Lo que corre en el host es separación de procesos, no un sandbox |

El resultado del runner vuelve por stdout en una línea `@@RESULT@@ <nonce> <json>` con un nonce por ejecución.
Resiste a código que imprime una línea de resultado falsa; no resiste a código que inspecciona su propio
intérprete.

### Quién tiene acceso a Docker

Ningún contenedor del stack tiene el socket de Docker. Lo usan procesos del host: `fleet` (contenedores de prod y
de los clones; solo elimina contenedores con su propia etiqueta), `pipeline` (lanza los contenedores runner con
`docker run`) y la CLI `immune` (`docker compose`, y contenedores de `init` y `doctor`). Fuera de un stack de
`immune up`, también usan Docker los scripts de los laboratorios, `immune fuxa` y `sidecar.prodwatch`, cuyo
contenedor trazador es `--privileged`.

### Autenticación entre componentes

- La API de `fleet` exige el header `x-admin-token` en todas sus rutas, comparado en tiempo constante. `fleet` no
  arranca sin `ADMIN_TOKEN` en su entorno.
- La API de administración del gateway (`/_admin/*`, puerto 8081) usa el mismo token.
- Publicar en el bus (`POST /events`) exige `x-bus-token`. Las lecturas son públicas y, sin token, llegan tachadas
  ([`dashboard/README.md`](../dashboard/README.md)).
- Prod y los clones no comparten secreto: `PROD_APP_SECRET` y `SHADOW_APP_SECRET` son distintos. Un token firmado
  con el secreto de los clones que llega desde fuera es evidencia directa.
- El WAF de detección, cuando está configurado, recibe del gateway el request completo (headers y cuerpo) por HTTP
  sin autenticación; debe estar en una red que solo el gateway alcance.
- Los cuatro secretos son aleatorios por proyecto y viven en `<runtime>/secrets.env` ([operacion.md](operacion.md)).

## 7. Diseñado y construido

Estado de cada elemento del diseño. "Construido" significa implementado y cubierto por tests. "Parcial" indica qué
parte existe. Cuando algo está implementado pero no se verificó de punta a punta, la fila lo dice. Las razones del
diseño están en [decisiones.md](decisiones.md).

| Elemento del diseño | Estado | Dónde |
|---|---|---|
| Veredicto por ejecución en un clon, no por puntaje | Construido | `gateway/core.py`, `shadow/` |
| Oráculos explícitos: SQL, archivo, proceso, red, dueño | Construido | `shadow/`, `sidecar/` |
| Honeytoken como pegamento de identidad | Parcial: un token firmado con el secreto de los clones visto desde fuera es evidencia; no hay credenciales señuelo plantadas | `immune/auth.py`, `gateway/core.py` |
| Confianza de identidad en vez de "autenticado" | Parcial: comprobación binaria por uid de la semilla; sin gradación por antigüedad, MFA o pagos | `gateway/classifier.py` |
| Señuelos procedurales L0 | Parcial: lista fija de rutas de escáner; sin paginación infinita ni goteo lento | `gateway/l0.py` |
| Clones compartidos de detonación L1 y clon cautivo L2 | Construido | `gateway/pool.py`, `fleet/` |
| Tope de cautivos por origen, pausa y bajada a disco | No construido (solo tope global y vencimiento por inactividad) | `gateway/pool.py` |
| Internet falso para el tráfico saliente de los clones (DNS, HTTP, metadata de nube) | No construido: los clones están en redes internas y el oráculo `net` dispara en el `connect` | `deploy/compose.yaml`, `shadow/instrument.py` |
| Reglas acotadas a ruta + parámetro + gramática, solo en el camino a prod | Construido. Alcances `param`, `param_present` y `all`; identidad `untrusted` opcional; sin TTL por defecto, TTL opcional | `gateway/classifier.py`, `patcher/rule.py`, `pipeline/rules.py` |
| Regla probada contra un corpus legítimo antes de activarse; reversión automática; presupuesto de reglas | No construido: la regla solo se valida contra su esquema. El gateway cuenta por regla los requests negados sin oráculo (`stats.denied`), pero nada actúa sobre ese contador | `pipeline/rules.py`, `gateway/core.py` |
| Firmas negativas (OWASP CRS) como señal de detonación, no de bloqueo | Parcial: cliente en el gateway y servicio Coraza construidos; no integrados en `immune up`, usados solo en el laboratorio de ScadaBR; sin test que ejecute Coraza | `gateway/waf.py`, `waf/` |
| El agente propone, deciden validaciones mecánicas | Construido (cinco validaciones) | `pipeline/gates.py` |
| Revisor independiente, un segundo modelo que solo ve el diff | No construido | — |
| Repetición diferencial de tráfico legítimo | Construido (escenarios guionados; GET grabados como alternativa) | `pipeline/gates.py` |
| Familia de variantes del PoC | Construido | `patcher/variants.py` |
| PoC que no reproduce 3 de 3: contener y escalar a una persona | Construido | `Pipeline.escalate` en `pipeline/orchestrator.py` |
| Blue/green con rollback automático | Construido | `fleet/manager.py` |
| Canario de despliegue antes del cambio de upstream | Construido. Probado sin Docker, con un gateway guionado y con un gateway real en proceso (`fleet/tests/test_canary.py`); no ejercitado con tráfico de usuarios. Con menos de `CANARY_MIN_REQUESTS` requests en la ventana no decide nada | `fleet/manager.py`, `gateway/core.py` |
| Snapshot del clon antes del request como estado del PoC | Parcial: SQLite sí; nulo para Postgres y MySQL | `contracts/product.md` |
| Auditoría de clase después de un parche ("memoria inmunológica") | Construido (python-asgi) | `pipeline/audit.py` |
| Muestreo de tráfico limpio, gramática aprendida por parámetro, huella de actor | Parcial: solo la línea base de estructura de sentencias SQL del sidecar, aprendida de las grabaciones limpias y usada con `sql_log`. Sin gramática por parámetro ni huella de actor | `sidecar/learn.py`, `sidecar/sqllog.py` |
| Atacante de demostración que repite los exploits documentados de la tienda | Construido | `sim/attacker.py` |
| Prueba de vulnerabilidad ciega, equipo rojo, suite de punta a punta | No construido | — |
| Oráculos fuera del proceso para cualquier lenguaje | Construido con `strace` (ptrace). Bases: proxy de Postgres y de MySQL/MariaDB, o registro de sentencias. Pila de aplicación solo para PHP con Xdebug | `sidecar/` |
| Oráculos fuera del proceso con eBPF o seccomp-notify en los clones | No construido. eBPF (`bpftrace`) se usa solo en el vigilante de prod | `sidecar/prodwatch.py` |
| Oráculos de syscalls sobre prod, solo alerta | Parcial: construido y usado en el laboratorio de Grafana; no integrado en `immune up`; los tests no ejecutan `bpftrace` | `sidecar/prodwatch.py` |
| Parche automático para una aplicación externa compilada (Go) | Parcial: construido para el laboratorio de Grafana, guiado por un `target.yaml` escrito a mano; tests unitarios de las partes (`pipeline/tests/test_extfix.py`); el ciclo completo no tiene test automático | `pipeline/extfix.py`, `labs/grafana-cve-2021-43798/` |
| `immune deploy` delante de un servicio existente | No construido (esbozo experimental) | `immune/deploycmd.py` |
| `immune init` para apps que no son Python | No construido. Para un proyecto PHP con MySQL, `init` solo detecta el caso y valida una configuración escrita a mano (comprobaciones 1 y 9 del doctor) | `immune/init.py`, `examples/tareas-node/.immune/`, `examples/openemr/overlay/.immune/` |
| Pull requests en GitHub | Implementado; verificado solo contra un `gh` simulado | `pipeline/repo.py` |
| Firecracker, XDP, puntaje con GBDT, LLM dentro del señuelo, eBPF-LSM | Fuera de alcance por decisión | — |
| Arranque al iniciar la máquina | No construido | — |
