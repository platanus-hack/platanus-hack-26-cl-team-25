# Límites

Tipo de documento: explicación. Es la lista única de límites, puntos ciegos y partes no construidas de Immune,
agrupada por componente. Los demás documentos enlazan aquí.

El límite principal: **el sistema aprende solo de lo que sus oráculos ven.** Un ataque que no dispara ningún
oráculo en el clon no abre incidente, no genera regla y no se parcha. Los oráculos no se corrigen solos.

Vocabulario de estado, igual que en la tabla de [arquitectura.md](arquitectura.md#7-diseñado-y-construido):
construido, parcial, no construido, fuera de alcance.

## Alcance general

- Protege la capa HTTP de una aplicación web. No cubre otros protocolos, credenciales por defecto ni accesos
  remotos expuestos.
- Clases de defecto con propiedades de validación propias: inyección SQL, path traversal e IDOR de lectura.
- No disparan ningún oráculo: fallas de lógica de negocio, IDOR de escritura, y ataques de segundo orden salvo
  que algo dentro del clon ejecute el payload guardado.
- Los defectos de las tres aplicaciones de demostración están plantados por el equipo, no descubiertos. Las
  listas están en `docs/demo/respuestas/`.
- Las fallas de los casos sobre software de terceros (Grafana, Apache httpd, ScadaBR, OpenEMR) son públicas o
  vienen de un aviso: el sistema recibe el request del aviso. Ningún caso es un descubrimiento.
- El hash de contraseñas con SHA-256 sin sal en `victim/app/auth.py` y `examples/notas/notas/auth.py` es una
  simplificación de las aplicaciones de demostración. No es un defecto plantado y está fuera de alcance.
- La detonación agrega latencia a los requests sospechosos. No está medida ([resultados.md](resultados.md)).
- No hubo revisión independiente, equipo rojo ni prueba con una vulnerabilidad plantada a ciegas
  ([proceso.md](proceso.md)).

## Gateway

- **Falla abierto sin regla.** Un veredicto `inconclusive` del clon (401, 404 o 5xx) sin regla activa deja pasar
  el request a prod. Lo mismo ocurre cuando no hay clon libre y el request no tiene señal fuerte.
- **Los clones corren la semilla.** Un objeto creado en prod después de la semilla da 404 en el clon. Un IDOR
  sobre ese objeto obtiene un veredicto `inconclusive` y puede llegar a prod.
- **Objetos fuera del manifiesto.** La comprobación de dueño para identidades de la semilla
  (`owner_scoped:mismatch`) solo marca objetos que el manifiesto atribuye a otro. Los que no figuran no se marcan.
- **Confianza binaria.** Una identidad es confiable si su uid es de la semilla. No hay gradación por antigüedad,
  MFA ni pagos. Una cuenta real comprometida se trata como confiable: nunca queda cautiva.
- **`gwsid` no está firmada.** La cookie la aporta el cliente. El cautiverio de un cliente anónimo depende de que
  conserve la cookie; si la descarta, vuelve a empezar como sesión nueva.
- **Regla incorporada de traversal.** Solo reconoce segmentos `..`, en sus formas codificadas conocidas.
- **Rutas fuera del OpenAPI.** Se clasifican como limpias salvo que coincidan con una regla, con la regla
  incorporada de traversal o con la lista L0, o que traigan un parámetro de consulta duplicado o un honeytoken.
- **Campos no inspeccionados.** Los marcados `x-sensitive`, y los headers y cookies que el OpenAPI no declara.
- **Una regla es tan fuerte como el oráculo.** Una regla fuerza la detonación; si el clon dice `clean`, el request
  pasa a prod. La regla se publica después del paso de reproducción: los incidentes en cola no la tienen hasta
  que les llega el turno.
- **Reglas sin prueba previa.** Una regla se valida contra su esquema. No se prueba contra tráfico legítimo antes
  de activarse, no hay reversión automática ni presupuesto de reglas (no construido). El gateway cuenta por regla
  los requests negados sin oráculo (`stats.denied` en `GET /_admin/rules`); nada actúa sobre ese contador.
- **Costo de una regla `param_present`.** Detona todo request que trae el parámetro, también el legítimo: agrega
  la latencia de una detonación a todo el tráfico de ese parámetro y ocupa clones L1. Cuando no hay clon libre en
  0.3 s, ese tráfico recibe 404 aunque el valor esté dentro de la gramática.
- **Costo de una regla `all`.** Niega todo request de la ruta cuyo veredicto en el clon es `inconclusive`. Un
  usuario real que pide un objeto creado después de la semilla recibe 404 mientras la regla esté activa.
- **Reglas sin vencimiento.** Por defecto una regla no tiene TTL. La de un incidente `escalated`, o la de un
  incidente cuyo parche no llega a desplegarse, queda activa hasta que alguien la borra
  (`DELETE /_admin/rules/<id>`) o hasta `immune reset`.
- **`PIPELINE_RULE_TTL_S` no alcanza a todas las reglas.** Solo se aplica a la regla incorporada del pipeline. La
  que deriva `patcher.derive_rule` lleva `ttl_s` nulo de forma explícita y no toma ese valor.
- **Reglas por identidad.** `identity: untrusted` exime a toda identidad confiable. Una cuenta de la semilla
  comprometida no es alcanzada por esa regla.
- **WAF de detección.** Opcional y fuera de `immune up`. Falla abierto: si no responde en 1.5 s el request queda
  limpio. Solo se consulta en modo `enforce` y solo para requests ya clasificados como limpios; agrega un viaje
  HTTP a cada uno de ellos, sin medir. El gateway le envía headers y cuerpo completos, sin autenticación. No hay
  ajuste de reglas CRS ni medición de falsos positivos; un falso positivo cuesta una detonación.
- **L0 es una lista fija** de 22 rutas de escáner y dos prefijos (`SCANNER_PATHS` en `gateway/l0.py`). Sin
  paginación infinita ni goteo lento.
- **Honeytoken parcial.** Solo el token firmado con el secreto de los clones. No hay credenciales señuelo
  plantadas.
- **Sesiones cautivas.** Tope global, desalojo de la más antigua y vencimiento por inactividad. Sin tope por
  origen, pausa ni bajada a disco (no construido).
- **Request truncado.** Si el cliente se desconecta a mitad del cuerpo, el request se descarta sin registrarse.
- **Eventos de tráfico.** Si el bus no responde, los eventos `request.*` del gateway se pierden. Sus demás eventos
  se reintentan durante 120 segundos, con un máximo de 2000 retenidos. Los eventos de `fleet` no se reintentan.
- **`aftercheck`** está desactivado por defecto. Activado, no detiene la primera respuesta, y bajo carga cubre lo
  que su presupuesto permite.
- **Conexiones lentas.** Un cliente que mantiene miles de conexiones lentas no está contemplado; requiere un
  proxy inverso delante.

## Oráculos en proceso (`shadow/`, aplicaciones Python ASGI)

- **SQL:** solo ve sentencias ejecutadas a través de `sqlite3`. No ve una sentencia que falla, ni una entrada que
  la aplicación transforma más allá de decodificarla o cambiarle mayúsculas.
- **Archivo:** no ve lecturas indebidas dentro de las raíces permitidas.
- **Dueño:** no ve una fuga en una ruta pública. Si el perfil no devuelve marcadores, el oráculo queda apagado,
  con un aviso en el registro. Si `load_markers` lanza una excepción, el clon no arranca.
- **Red:** una aplicación que hace llamadas salientes legítimas dispara el oráculo `net`. No hay internet falso
  que las simule (no construido).
- Los hooks corren solo en los clones.

Detalle en `shadow/README.md`.

## Oráculos fuera del proceso (`sidecar/`, runtime genérico)

- **Syscalls observadas:** `openat`, `openat2`, `open`, `creat`, `execve`, `execveat`, `connect`, `sendto`,
  `sendmsg`, `fork`, `vfork`, `clone`, `clone3`. **No se observan:** lecturas sobre descriptores ya abiertos,
  `rename`, `unlink`, `mmap`, io_uring ni bases de datos embebidas en el proceso.
- Aperturas y ejecuciones fallidas no cuentan como observación.
- **Bases soportadas: Postgres y MySQL/MariaDB.** El proxy de Postgres responde `N` a `SSLRequest` y
  `GSSENCRequest`, y el de MySQL quita TLS y compresión del saludo del servidor: la conexión entre la aplicación y
  la base del clon es siempre en claro, y una aplicación que exige TLS a su base no conecta. Se comprueba el texto
  de las sentencias; los parámetros enlazados (`Bind`, `COM_STMT_EXECUTE`) no. Una aplicación que abre su propia
  conexión directa a la base, sin pasar por el proxy, no tiene oráculo `sql`. Las bases embebidas en el proceso
  (SQLite, H2) no se ven.
- **MySQL está menos probado que Postgres.** El proxy de MySQL tiene tests unitarios y un test con una MariaDB
  real (`sidecar/tests/test_mysqlproxy.py`, marcado `docker`, que se omite si la imagen fijada no está). El stack
  completo con MySQL solo se ejercitó a mano sobre OpenEMR ([resultados.md](resultados.md)).
- **Registro de sentencias (`sql_log`).** El registro no dice si una sentencia se ejecutó: todas cuentan como
  ejecutadas, salvo las que Postgres repite tras un error. El analizador del registro de MySQL solo tiene tests
  unitarios.
- **Regla de estructura (`new_structure`).** Está apagada hasta que se aprende un request. La línea base es global,
  no por ruta. Una estructura legítima que nunca se aprendió dispara: los falsos positivos dependen del tráfico
  usado para aprender. Los requests que necesitan sesión solo enseñan algo si las credenciales grabadas valen en
  el clon, y la grabación del gateway las tacha.
- **Sin constantes de la aplicación o con MySQL**, una coincidencia del oráculo `sql` sobre un solo token se
  descarta: no se distingue de un identificador que escribió la aplicación.
- **Pila solo para PHP.** La evidencia trae pila de aplicación únicamente con `shadow.tracer.kind: php-xdebug`. En
  los demás casos no trae archivo ni línea, y el generador de parches localiza el punto a partir de la ruta, el
  parámetro y la sentencia o ruta de archivo observada.
- **Estado del PoC:** el estado previo del clon es nulo para Postgres y MySQL.
- **Modo `docker`.** Traza el PID 1 del contenedor y los hijos que arranca después de unirse; otros procesos ya en
  marcha no se trazan.
- **`protected_paths`.** Con esa clave el oráculo `file` solo mira las rutas protegidas; una lectura indebida de
  cualquier otro archivo no dispara.
- **Trazador caído:** si muere antes del request, el clon responde 503 y el veredicto es `inconclusive`; si muere
  durante el request, `inconclusive`. Sin regla activa, eso falla abierto en el gateway.
- Requiere la capacidad `SYS_PTRACE` en el contenedor observador. Está implementado con `strace`, que detiene el
  proceso del clon en cada syscall trazada; eBPF y seccomp-notify en los clones no están construidos.
- Con tests de integración: una aplicación Node y una aplicación en C enlazada estáticamente
  (`sidecar/tests/test_integration.py`). Ejercitado a mano, sin test automático: Grafana (Go), ScadaBR (Java, solo
  con el oráculo de `sidecar/httpds`) y OpenEMR (PHP).
- La auditoría de clase está desactivada por defecto en este runtime, y no hay parches de respaldo.

Detalle en `sidecar/README.md`.

## Vigilante de prod (`sidecar/prodwatch.py`)

- Solo alerta, y después del hecho: el request ya se ejecutó en prod.
- No está integrado en `immune up`. Solo lo arranca el laboratorio de Grafana.
- El contenedor trazador es `--privileged` (lo exige eBPF), sin red.
- Solo `openat`, `execve` y `connect`. No tiene oráculo `sql` ni `owner`.
- La atribución es por instante, no por request: con tráfico concurrente hay varios candidatos, y "confirmado"
  significa que uno de ellos dispara en el clon, no que sea el causante del evento.
- La grabación del gateway tacha cookies y `authorization`: un ataque autenticado no se puede repetir en el clon.
- Lo que el contenedor hace en sus primeros segundos (`PROD_GRACE_S`) se aprende como normal.
- Los tests no ejecutan `bpftrace`.

## Validaciones y pipeline

Qué no detecta cada validación está junto a su descripción en [validaciones.md](validaciones.md). En resumen:

- **`policy` es heurística.** No sigue el flujo de datos. No ve una puerta trasera semántica que no necesite un
  literal, un import ni una lectura nueva del request. Para código que no es Python es léxica.
- **`properties` y `poc` usan conjuntos fijos de entradas** y dependen de los oráculos.
- **`legit` del demo es sintético:** cinco escenarios guionados, no tráfico de usuarios.
- **No hay segundo modelo revisor** (no construido).
- **Inyección de prompt.** El payload del atacante llega al modelo como dato delimitado. La defensa contra un
  parche dirigido es el confinamiento de herramientas más las validaciones.
- **Confinamiento del modelo.** Lo aplica la CLI `claude` con sus opciones; no hay un sandbox del sistema
  operativo alrededor de ese proceso. El código de la aplicación y la evidencia salen hacia el proveedor del
  modelo.
- **Runner.** El nonce del resultado resiste a salidas impresas falsas, no a código que inspecciona su propio
  intérprete.
- **Un incidente a la vez.** Los demás esperan en cola.
- **PoC que no reproduce 3 de 3.** El incidente queda contenido por la regla y sin parche (`escalated`). Nada
  avisa a una persona fuera del evento del bus y del panel.
- **Etapa de parche para aplicaciones externas (`pipeline/extfix.py`).** Sus validaciones no son las cinco de
  [validaciones.md](validaciones.md): no hay `properties`, y su `policy` solo comprueba la zona editable, el
  tamaño y una lista corta de construcciones. Necesita un `target.yaml` escrito a mano por aplicación. Solo existe
  el del laboratorio de Grafana. El ciclo completo no tiene test automático.
- **Parche de ScadaBR.** Lo producen scripts del laboratorio, no el pipeline. El parche compilado se prueba en un
  contenedor candidato aparte; el contenedor de prod del laboratorio no se reemplaza
  (`labs/scadabr-cve-2026-8602/verify_patch.sh`).
- **Parches de respaldo** solo para la tienda de demostración.
- **Pull requests en GitHub:** implementados, verificados solo contra un `gh` simulado. El demo usa
  `repo.target: local`.
- **Auditoría de clase:** deriva candidatos del OpenAPI. No ve rutas que no están en él. Activa por defecto solo
  para `python-asgi`.

## Despliegue (`fleet/`)

- El rollback posterior al cambio observa solo la tasa de 5xx, solo durante la ventana (20 segundos por defecto) y
  solo con un mínimo de requests. No ve un comportamiento incorrecto que responde 200 ni nada posterior a la
  ventana.
- El canario de despliegue compara tasas de 5xx y de 4xx entre los dos releases, durante 8 segundos por defecto
  y con el 20 % del tráfico. No compara cuerpos de respuesta. Con menos de 20 requests en el lado canario no
  decide nada (`skipped`) y el despliegue sigue.
- El reparto del canario es por request, no por sesión: durante la ventana un mismo cliente puede ser atendido
  por los dos releases.
- Con poco tráfico el despliegue se acepta sin validación por tráfico (`traffic_validated: false`).
- Un atacante que eleva la tasa de 5xx del release nuevo solo durante la ventana puede provocar un rollback. Las
  comparaciones contra la tasa del release anterior lo dificultan, no lo impiden.
- El canario no existe en el despliegue de `pipeline/extfix.py` ni en `immune fuxa`.
- El request de humo se omite cuando el OpenAPI no tiene un GET público sin parámetros.
- Los dos colores comparten la base de prod. Un parche que cambie el esquema de la base no está contemplado.

## `immune init` y `immune doctor`

- **Alcance:** aplicaciones Python ASGI que exponen `openapi()` (FastAPI) con un archivo SQLite. Para otros
  lenguajes `init` no genera nada (no construido): los perfiles de `examples/tareas-node` y `examples/openemr`
  están escritos a mano. Ante un proyecto PHP con MySQL, `init` solo valida la configuración existente con las
  comprobaciones 1 y 9 del doctor.
- **`immune doctor` en un proyecto genérico con MySQL** ejecuta solo las comprobaciones 1 y 9; las demás se
  informan como omitidas. No comprueba identidad, oráculos, reinicio del clon ni fugas de datos reales.
- **Código generado que corre en el host.** `profile.py` lo escribe el modelo, pasa una lista estática de
  construcciones prohibidas y se importa en el host con el usuario que invoca. Las comprobaciones 2 a 5 del doctor
  también corren en el host. El volcado del OpenAPI se intenta primero en un contenedor `--network none` y corre
  en el host solo si Docker no está disponible o ese intento falla (`dump` en `immune/initsteps/openapi.py`). Lo
  que corre en el host es separación de procesos, no un sandbox.
- **Perfil incorrecto en silencio.** Un perfil puede marcar como pública una ruta privada. Lo mitigan las
  comprobaciones del doctor y la revisión de `report.md`; no hay mitigación completa.
- **Datos reales en los clones.** Clasificar mal una columna puede llevar datos reales a la semilla sintética. La
  comprobación 6 lo cubre por muestreo, no por garantía.
- **Heurísticas ajustadas a las aplicaciones de demostración:** la detección del borrador de autenticación
  (`immune/initsteps/drafts.py`), `FILE_PARAM_RE` (`immune/initsteps/scenarios.py`) y las claves del manifiesto en
  plural inglés (`immune/shadowdata.py`).
- **Sin OpenAPI ni tests** el valor baja: la clasificación es más débil y `autopatch` queda limitado a `pr`.

## Dashboard

- Las lecturas son públicas. Un lector sin token recibe los eventos tachados, pero ve método, ruta, parámetros no
  sensibles, claves de sesión `uid:<n>`, pilas, diffs, detalle de las validaciones, gramáticas de las reglas y
  tiempos. El JSONL en disco nunca se tacha.
- El panel "Bot atacante" aparece solo si la corrida tiene eventos `attack.attempt`. Los emite el atacante de
  demostración `sim/attacker.py`, que repite los siete exploits documentados de la tienda; no busca defectos
  nuevos y solo apunta a un gateway en la misma máquina. `dashboard/demo_events.py` también los emite, con datos inventados y la etiqueta "DEMO".

Detalle en `dashboard/README.md`.

## Demo de FUXA (`immune fuxa`)

- Es un camino aparte: gateway propio en Node, controles de autorización dentro del servidor FUXA y dashboard
  propio. No usa clones, oráculos de ejecución ni las cinco validaciones de [validaciones.md](validaciones.md).
- `immune fuxa demo` entrega evidencia sintética, marcada como tal: no hay un ataque real detectado en esa demo.
- Las conexiones WebSocket y los mensajes de polling de más de 64 KiB no se inspeccionan en el gateway.
- Cubre las operaciones declaradas en su inventario; las demás figuran como pendientes.

Detalle en [fuxa.md](fuxa.md).

## Ejemplo de OpenEMR (`examples/openemr/`)

- El oráculo `owner` no cubre los datos de pacientes: OpenEMR controla el acceso por ACL y no por dueño.
- Tres de las cinco detecciones dependen de oráculos escritos a mano para esta aplicación en el perfil
  (`extra_oracles` en `examples/openemr/overlay/.immune/openemr_identity.py`), y una, de una regla que siembra el
  operador (`examples/openemr/seed-rules.sh`). No son oráculos generales.
- Sin la CLI `claude` no hay parche: el runtime genérico no tiene parches de respaldo.
- La validación `tests` de este ejemplo es `php -l` más un arranque de la aplicación, no una suite.

Detalle en [openemr.md](openemr.md).

## Laboratorios (`labs/`)

- No usan `immune up`, `fleet` ni `deploy/compose.yaml`: el gateway y los demás procesos corren en el host y los
  contenedores se publican en `127.0.0.1`, sin las redes internas de un stack.
- Grafana: el oráculo `file` solo mira los archivos protegidos de `sidecar.json`. El pull request es una rama en
  un clon local, no un PR en GitHub.
- ScadaBR: la credencial de los dispositivos legítimos la modela el gateway; ScadaBR 1.2.0 no tiene ninguna en
  ese endpoint. El oráculo lee la respuesta de la propia aplicación (`Unconsumed key`), no syscalls ni pila.
- Ningún laboratorio tiene test automático de punta a punta.

## Operación

- **`immune deploy` no es un camino de protección.** Es un esbozo experimental: el gateway que arranca no tiene
  pool de clones ni bus. Poner el gateway delante de un servicio existente del cliente no está construido.
- Nada levanta el stack al iniciar la máquina.
- No hay integración continua.
- `install.sh` está probado solo en Ubuntu 24.04 ARM64.
- No está contemplada la pérdida de la máquina ni del propio Docker.
- El Postgres de demostración del runtime genérico no está supervisado.
- El generador de parches usa por defecto el login de Claude Code de la máquina y su cuota. Se le puede dar una
  identidad propia con `PATCHER_CLAUDE_CONFIG_DIR` o `PATCHER_ANTHROPIC_API_KEY` ([operacion.md](operacion.md)).
  El proceso `claude` no hereda el entorno del pipeline: recibe una lista permitida de variables, sin los secretos
  del stack. Sigue sin haber un sandbox del sistema operativo alrededor de ese proceso.

## Resultados

- Las cifras de tiempo de la tienda son anteriores a las correcciones del 2026-11-22 y al canario de despliegue,
  y no se volvieron a medir; en ese momento la lista de defectos estaba al alcance del generador de parches. Ver
  la advertencia de [resultados.md](resultados.md).
- Los resultados de Grafana, ScadaBR, OpenEMR y FUXA no tienen datos crudos en el repositorio.
- El caso de Apache usa un defecto público: demuestra el mecanismo, no un descubrimiento a ciegas.

## No construido

Elementos del diseño que no existen en el código, o que existen solo en parte. La tabla de
[arquitectura.md](arquitectura.md#7-diseñado-y-construido) da el estado de cada elemento y dónde está.

| Elemento | Estado | Nota |
|---|---|---|
| Internet falso para el tráfico saliente de los clones | No construido | Permitiría detectar SSRF y capturar la segunda etapa sin delatar el clon |
| Regla probada contra tráfico legítimo, reversión automática, presupuesto de reglas | No construido | |
| Revisor independiente con un segundo modelo | No construido | |
| Tope de cautivos por origen, pausa y bajada a disco | No construido | |
| Gramática aprendida por parámetro, huella de actor | No construido | Lo único que se aprende del tráfico limpio es la línea base de estructura SQL del sidecar |
| Prueba de vulnerabilidad ciega, equipo rojo, suite de punta a punta | No construido | El atacante de demostración (`sim/attacker.py`) solo repite exploits conocidos |
| Oráculos con eBPF o seccomp-notify en los clones | No construido | Los clones usan `strace`. `bpftrace` solo en el vigilante de prod |
| Vigilante de prod y WAF de detección dentro de `immune up` | Parcial | Existen como piezas; solo los arrancan los laboratorios |
| `immune deploy` delante de un servicio existente | No construido | |
| `immune init` para aplicaciones que no son Python | No construido | Perfil escrito a mano |
| Adaptadores para otras bases; hooks en proceso para Node | No construido | El runtime genérico soporta Postgres y MySQL/MariaDB |
| Pila de aplicación en la evidencia del runtime genérico | Parcial | Solo PHP con Xdebug |
| Parche automático de aplicaciones externas sin `target.yaml` escrito a mano | No construido | |
| Aviso a una persona cuando un incidente se escala | No construido | Solo el evento del bus |
| Arranque al iniciar la máquina | No construido | |
| Prueba sobre un aviso posterior a la fecha de corte del modelo | No construido | Necesaria para afirmar descubrimiento a ciegas en el modo de anticipación |

Fuera de alcance por decisión: Firecracker, XDP, puntaje con GBDT, LLM dentro del señuelo, eBPF-LSM.
