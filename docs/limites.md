# Límites

Tipo de documento: explicación. Es la lista única de límites, puntos ciegos y partes no construidas de Inmune,
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
  pasa a prod. La regla solo existe después de que el PoC reproduce 3 de 3: un incidente `not_reproducible` no
  tiene regla, y los incidentes en cola no la tienen hasta que les llega el turno.
- **Reglas sin prueba previa.** Una regla se valida contra su esquema y debe rechazar el valor capturado. No se
  prueba contra tráfico legítimo antes de activarse, no hay reversión automática ni presupuesto de reglas (no
  construido).
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
- **Solo Postgres.** El proxy responde `N` a `SSLRequest` y `GSSENCRequest`: rechaza TLS entre la aplicación y la
  base. Comprueba el texto de las sentencias `Q` y `Parse`; no comprueba los parámetros de `Bind`.
- **Sin pila.** La evidencia no trae archivo ni línea. El generador de parches localiza el punto a partir de la
  ruta, el parámetro y la sentencia o ruta de archivo observada.
- **Estado del PoC:** el estado previo del clon es nulo para Postgres.
- **Trazador caído:** si muere antes del request, el clon responde 503 y el veredicto es `inconclusive`; si muere
  durante el request, `inconclusive`. Sin regla activa, eso falla abierto en el gateway.
- Requiere la capacidad `SYS_PTRACE` en el contenedor observador. Está implementado con `strace`; eBPF y
  seccomp-notify no están construidos.
- Probado con una aplicación Node y con una aplicación en C enlazada estáticamente
  (`sidecar/tests/test_integration.py`). No probado con otros lenguajes.
- La auditoría de clase está desactivada por defecto en este runtime, y no hay parches de respaldo.

Detalle en `sidecar/README.md`.

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
- **Parches de respaldo** solo para la tienda de demostración.
- **Pull requests en GitHub:** implementados, verificados solo contra un `gh` simulado. El demo usa
  `repo.target: local`.
- **Auditoría de clase:** deriva candidatos del OpenAPI. No ve rutas que no están en él. Activa por defecto solo
  para `python-asgi`.

## Despliegue (`fleet/`)

- El rollback observa solo la tasa de 5xx, solo durante la ventana (20 segundos por defecto) y solo con un mínimo
  de requests. No ve un comportamiento incorrecto que responde 200 ni nada posterior a la ventana.
- Con poco tráfico el despliegue se acepta sin validación por tráfico (`traffic_validated: false`).
- Un atacante que eleva la tasa de 5xx solo durante la ventana puede provocar un rollback.
- El request de humo se omite cuando el OpenAPI no tiene un GET público sin parámetros.
- Los dos colores comparten la base de prod. Un parche que cambie el esquema de la base no está contemplado.

## `immune init` y `immune doctor`

- **Alcance:** aplicaciones Python ASGI que exponen `openapi()` (FastAPI) con un archivo SQLite. Para otros
  lenguajes no hay `init` (no construido); el perfil de `examples/tareas-node` está escrito a mano.
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
- **`immune doctor` e `immune deploy` sin `--project`** actúan sobre el checkout de Inmune, no sobre el
  directorio actual.
- **Sin OpenAPI ni tests** el valor baja: la clasificación es más débil y `autopatch` queda limitado a `pr`.

## Dashboard

- Las lecturas son públicas. Un lector sin token recibe los eventos tachados, pero ve método, ruta, parámetros no
  sensibles, claves de sesión `uid:<n>`, pilas, diffs, detalle de las validaciones, gramáticas de las reglas y
  tiempos. El JSONL en disco nunca se tacha.
- El panel "Bot atacante" aparece solo si la corrida tiene eventos `attack.attempt`. Los emite el atacante de
  demostración `sim/attacker.py`, que repite los siete exploits documentados de la tienda; no busca defectos
  nuevos. `dashboard/demo_events.py` también los emite, con datos inventados y la etiqueta "DEMO".

Detalle en `dashboard/README.md`.

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

- Las cifras de tiempo son anteriores a las correcciones del 2026-11-22 y no se volvieron a medir; en ese momento
  la lista de defectos estaba al alcance del generador de parches. Ver la advertencia de
  [resultados.md](resultados.md).
- El caso de Apache usa un defecto público: demuestra el mecanismo, no un descubrimiento a ciegas.

## No construido

Elementos del diseño que no existen en el código. La columna "Dónde" de la tabla de
[arquitectura.md](arquitectura.md#7-diseñado-y-construido) indica el punto de partida de cada uno.

| Elemento | Nota |
|---|---|
| Internet falso para el tráfico saliente de los clones | Permitiría detectar SSRF y capturar la segunda etapa sin delatar el clon |
| Regla probada contra tráfico legítimo, reversión automática, presupuesto de reglas | |
| Revisor independiente con un segundo modelo | |
| Tope de cautivos por origen, pausa y bajada a disco | |
| Muestreo de tráfico limpio, gramática aprendida por parámetro, huella de actor | |
| Prueba de vulnerabilidad ciega, equipo rojo, suite de punta a punta | El atacante de demostración (`sim/attacker.py`) solo repite exploits conocidos |
| Oráculos con eBPF o seccomp-notify | Hoy `strace` y proxy de Postgres |
| `immune deploy` delante de un servicio existente | |
| `immune init` para aplicaciones que no son Python | |
| Adaptadores para MySQL y otras bases; hooks para Node en proceso | El runtime genérico solo soporta Postgres |
| Arranque al iniciar la máquina | |
| Prueba sobre un aviso posterior a la fecha de corte del modelo | Necesaria para afirmar descubrimiento a ciegas en el modo de anticipación |

Fuera de alcance por decisión: Firecracker, XDP, puntaje con GBDT, LLM dentro del señuelo, eBPF-LSM.
