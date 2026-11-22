# Decisiones de diseño

Tipo de documento: explicación. Registra por qué Inmune está diseñado como está: las fallas que tenía el primer
diseño, el cambio que responde a cada una y si ese cambio está construido.

Los estados usan el mismo vocabulario que la tabla "Diseñado y construido" de
[arquitectura.md](arquitectura.md#7-diseñado-y-construido), que es la referencia: **Construido**, **Parcial**,
**No construido**, **Fuera de alcance**. Lo que falta está reunido en [limites.md](limites.md).

## 1. Principios que se mantienen desde el primer diseño

- El clon corre el código real de la aplicación, no un servicio falso.
- Nada arranca en el camino de un request: los clones se toman de un pool que ya está en marcha.
- El PoC ejecutable es el artefacto central. Lo que propone el modelo solo vale si se verifica de forma mecánica.
- Dos velocidades de respuesta: primero una regla en el gateway, después un parche de código.

## 2. Fallas del primer diseño

El primer diseño decidía quién era atacante con un puntaje por sesión y lo desviaba a una microVM. Estas son las
fallas que llevaron al diseño actual. La columna "Cambio" remite a la sección 3.

### Críticas

| # | Falla | Por qué rompe la premisa | Cambio |
|---|---|---|---|
| F1 | La detección por puntaje necesita historial: tasa, entropía de rutas y tiempos son rasgos de sesión | Los primeros requests siempre llegan a prod. Un exploit de un solo disparo nunca se desvía. Solo se atrapa a los atacantes ruidosos | C1 |
| F2 | "Nunca desviar sesiones autenticadas" | Registrar una cuenta alcanza para quedar exento. Muchas fallas serias (IDOR, SQLi en rutas internas) están detrás del login | C1, C3 |
| F3 | Inyección de prompt al agente defensivo: el payload es texto del atacante y entra a un modelo cuyo resultado termina en prod | El atacante puede dirigir el parche: introducir una puerta trasera o desactivar un control | C7 |
| F4 | Autoinmunidad: bloqueo por huella y reglas autónomas "porque son reversibles" | Un atacante fabrica ataques con la forma del tráfico legítimo e induce una regla que deja fuera a los clientes reales | C1, C6 |
| F5 | Una microVM de un solo uso por huella | Rotar IP o huella no cuesta nada; cada rotación cuesta memoria al defensor. El pool se agota | C4 |

### Altas

| # | Falla | Consecuencia | Cambio |
|---|---|---|---|
| F6 | Oráculo diferencial: con un segundo punto de vista limpio el atacante compara respuestas | Datos públicos distintos o estado propio que no aparece delatan el señuelo. La clave "por huella" colisiona entre usuarios y se evade rotando | C5 |
| F7 | Tráfico saliente denegado sin simulación | SSRF, shells inversas y descarga de segunda etapa fallan en el señuelo y funcionarían en prod: delata la trampa | C5 |
| F8 | No se define qué significa "el exploit funcionó". Syscalls y capturas de red no ven fallas de lógica | IDOR y fallas de autorización no disparan nada | C2 |
| F9 | Validación de parche insuficiente: "el PoC falla y la suite pasa" lo cumple un parche que filtra ese payload exacto o que borra la funcionalidad | Parches sobreajustados: la variante siguiente vuelve a entrar | C7 |
| F10 | No se dice dónde aplican las reglas ni qué versión corre el cautivo | Si la regla también filtra el camino al señuelo, el atacante ve el cambio. Si prod se redespliega, el PoC queda validado contra una versión vieja | C6, C7 |
| F11 | Repetición reinyectando bytes desde una captura de red | Frágil con tokens de sesión, nonces y exploits de varios pasos. El gateway ya ve el texto plano | C8 |

### Medias

| # | Falla | Cambio |
|---|---|---|
| F12 | seccomp no se aplica en caliente a un proceso que ya corre; eBPF-LSM exige kernel y privilegios en el host del cliente. "En segundos" solo vale para la regla del gateway | C6 |
| F13 | La base de datos no está dimensionada: cada clon necesita su propio estado | C5 |
| F14 | Contradicción de soberanía: los payloads "no salen del país" pero el análisis y el modelo están fuera | C9 |
| F15 | Gateway propio en línea sin modo de falla definido: punto único de falla delante de prod | C9 |
| F16 | Sobreingeniería: XDP, puntaje con GBDT, orquestador de Firecracker, LLM dentro del señuelo | C9 |

## 3. Cambios de diseño y su estado

### C1. El veredicto lo da la ejecución, no un puntaje

La forma del request solo decide **a quién se detona**. Quién es atacante lo decide un oráculo. Un request
sospechoso se ejecuta primero en un clon; si ningún oráculo dispara, se reenvía a prod y el cliente recibe la
respuesta real. Un falso positivo cuesta latencia, no datos falsos. El contenido de un solo request alcanza para
marcarlo sospechoso, así que el primer request ya puede detonarse.

| Parte | Estado |
|---|---|
| Clasificación por request, detonación y decisión | Construido (`gateway/classifier.py`, `gateway/core.py`) |
| Cautiverio solo con evidencia mecánica; la sesión pasa a un clon L2 dedicado, que se asigna en su siguiente request | Construido (`gateway/core.py`, `gateway/pool.py`) |

Límite: la detonación pierde fidelidad cuando el request depende de datos que solo existen en prod.

### C2. Oráculos explícitos

Cinco comprobaciones de sí o no dentro del clon: estructura de la consulta SQL, apertura de archivo fuera de las
raíces permitidas, proceso hijo, conexión saliente y datos de otro dueño en la respuesta. El oráculo de dueño se
juzga sobre el cuerpo de la respuesta mediante marcadores por dueño, de modo que cubre filas, archivos y volcados
obtenidos por SQLi.

| Parte | Estado |
|---|---|
| Oráculos `sql`, `file`, `proc`, `net`, `owner` | Construido (`shadow/`, `sidecar/`) |
| Honeytoken (credencial falsa que identifica al mismo actor desde otra IP) | Parcial: solo el token firmado con el secreto de los clones |

Dos correcciones al oráculo SQL quedaron fijadas como tests: una consulta parametrizada con `O'Brien` no dispara,
y `a'--` sí. Por eso el oráculo compara valores de entrada contra tokens de la sentencia ejecutada, no la
estructura contra una plantilla.

### C3. Confianza de identidad en vez de "autenticado"

Una cuenta creada hace minutos puede ser del atacante y entra al flujo. Una identidad con confianza establecida no
recibe nunca datos sintéticos: si un oráculo dispara para ella, recibe una negativa genérica.

| Parte | Estado |
|---|---|
| Identidad confiable = uid de la semilla | Parcial: binario, sin antigüedad, MFA ni pagos |
| El gateway resuelve la identidad con el token de prod y la inyecta al clon por un header interno; el clon crea al usuario si no existe | Construido (`immune/auth.py`, `shadow/core.py`) |

Límite: una cuenta real comprometida y con buena reputación no se desvía. Para ella solo aplican las reglas y la
comprobación de dueño contra el manifiesto.

### C4. Señuelos por niveles

| Nivel | Qué es | Estado |
|---|---|---|
| L0 | Respuestas sin estado del gateway para rutas que la app no tiene | Parcial: lista fija; sin paginación infinita ni goteo lento |
| L1 | Clones compartidos de detonación, restaurados tras cada request | Construido |
| L2 | Clon dedicado para una sesión cautiva | Construido |
| Topes | Por origen y global; pausa y bajada a disco del cautivo inactivo | No construido salvo el tope global, el desalojo del más antiguo y el vencimiento por inactividad |

Si el pool se agota, el tráfico sin señal fuerte va a prod, protegido por las reglas vigentes.

### C5. Indistinguibilidad

| Parte | Estado |
|---|---|
| Datos públicos idénticos a prod; solo lo privado es sintético, con mismos ids y relaciones | Construido (`immune/shadowdata.py`, o el `data.seed_command` del proyecto) |
| Cada clon tiene su propia base, restaurada con la API de backup de SQLite, nunca copiando el archivo | Construido (`shadow/db.py`) |
| Internet falso: sumidero de DNS, HTTP y metadata de nube para el tráfico saliente del clon | No construido. Los clones están en redes internas y el oráculo `net` dispara en el `connect` |

Límite: el estado que el atacante escribe en el clon no es visible desde otra sesión.

### C6. Reglas que no pueden volverse contra el propio servicio

| Condición | Estado |
|---|---|
| Alcance mínimo: ruta + parámetro + gramática. Nunca huella, IP ni user-agent | Construido (`patcher/rule.py`) |
| Solo en el camino a prod: los clones siguen vulnerables, para que el cautivo no vea cambios | Construido |
| TTL y retiro cuando el parche está desplegado | Construido (TTL por defecto 3600 s) |
| Prueba contra un corpus de tráfico legítimo antes de activarse | No construido |
| Reversión automática y presupuesto de reglas activas | No construido |

Una regla no bloquea: fuerza la detonación de lo que no cumple la gramática, también para identidades confiables,
y falla cerrado solo cuando no hay clon o el veredicto es `inconclusive`. La regla de kernel queda fuera de alcance
(F12).

### C7. El agente propone, no decide

| Parte | Estado |
|---|---|
| La evidencia mecánica va primero; el payload entra como dato delimitado, nunca como instrucción | Construido (`patcher/core.py`, `render`) |
| El modelo no tiene herramientas de red ni de shell; su única salida es un diff | Construido (`patcher/claude_cli.py`) |
| Límites del diff: solo archivos bajo `app.source_dirs`, sin imports nuevos, sin accesos nuevos a red o procesos, tamaño acotado | Construido (validación `policy`, heurística) |
| Revisor independiente: un segundo modelo que ve solo el diff | No construido |
| Validaciones mecánicas en un runner aislado: propiedades por clase, PoC y variantes, tests, comportamiento legítimo | Construido ([validaciones.md](validaciones.md)) |
| Reproducción del PoC contra el release actual antes de parchear | Construido |
| Despliegue blue/green con rollback automático | Construido |

"El PoC falla y los tests pasan" lo cumple una lista negra o una puerta trasera. Por eso las validaciones exigen
propiedades positivas por clase y una política sobre el diff, y por eso existe un autotest con parches
inadecuados que deben ser rechazados.

### C8. Captura por estado, no por repetición de bytes

El gateway graba los requests en texto plano. Cuando un oráculo dispara, el PoC es el estado del clon antes del
request más el request. Eso cubre exploits de varios pasos sin reconstruir tokens ni nonces.

| Parte | Estado |
|---|---|
| Grabación de requests en el gateway | Construido (`<runtime>/recordings/requests.jsonl`) |
| Estado previo del clon como parte del PoC | Parcial: SQLite sí; nulo para Postgres |

Límite: un ataque de segundo orden solo se detecta si algo dentro del clon ejecuta el payload guardado.

### C9. Operación

| Parte | Estado |
|---|---|
| Falla abierto para el tráfico sin señal; falla cerrado para lo que coincide con una regla activa o tiene señal fuerte | Construido |
| El sistema corre entero en la infraestructura del cliente. Sale lo que se envía al proveedor del modelo: código de la app y evidencia del request | Construido; el proveedor es el login de Claude Code de la máquina |
| XDP, puntaje con GBDT, Firecracker, LLM dentro del señuelo, eBPF-LSM | Fuera de alcance por decisión |

## 4. Decisiones técnicas

| Tema | Decisión | Razón |
|---|---|---|
| Veredicto | Tres valores: `clean`, `oracle`, `inconclusive`. El gateway espera el cuerpo completo y la confirmación explícita del clon; sin confirmación es `inconclusive` | El header de veredicto de una respuesta en streaming sale antes de que la app abra el archivo: un traversal pasaría como limpio |
| Atribución | Un request a la vez por clon | Los eventos de oráculo se atribuyen por clon, no por contexto de ejecución |
| Control del clon | Sin puerto de control. Modo (L1 o L2) e identidad viajan en headers internos que solo el gateway puede poner; la evidencia sale firmada por clon hacia un puerto de solo ingesta | Un clon comprometido no debe poder reconfigurarse ni alcanzar la administración |
| Estado del clon | Restauración con la API de backup de SQLite | Copiar el archivo con la app en marcha deja una base vacía o las conexiones abiertas sobre el archivo viejo |
| Identidad en el clon | Prod y clones no comparten secreto; el gateway inyecta el uid | Una cuenta creada en prod no existe en el clon: sin esto la detonación da 401 y el exploit se reenviaría a prod |
| Cautiverio | Solo sesiones con clave reutilizable (identidad o cookie del gateway). Nunca por IP | Con clave por IP, el tráfico legítimo que comparte origen con el atacante quedaba cautivo |
| Regla | Fuerza detonación, alcanza a identidades confiables y falla cerrado | Una regla que solo "detona" no agrega nada: lo sospechoso ya se detonaba |
| Oráculo de dueño | Marcadores por dueño en la respuesta | Contar filas leídas disparaba en el login |
| Red | Prod y clones en redes internas; ningún contenedor tiene el socket de Docker | Un clon no debe tener ruta al gestor de contenedores ni a metadata de nube |
| Despliegue | El release se monta de solo lectura; la base de prod vive en un directorio compartido por los dos colores | Sin `docker build` en el camino del parche (runtime `python-asgi`); un cambio de color no pierde datos creados después de la semilla |
| Hooks | Los oráculos corren solo en los clones | El proceso de prod no se modifica |
| Repositorio | Cada corrida parte del tag de t0 en una rama propia (`run/<id>/base`); cada incidente usa `run/<id>/fix-<incidente>` | Volver a t0 no borra ni reabre pull requests |
| Publicación | Todos los puertos se enlazan a `127.0.0.1`. Si algo se expone fuera de la máquina, es el dashboard de solo lectura, con un proxy o túnel ajeno al repositorio; nunca el gateway con una app vulnerable detrás | El gateway del demo protege una app con defectos plantados |
| Parches de respaldo | Diffs escritos a mano, solo para la tienda de demostración, usados cuando el modelo no responde; pasan por las mismas validaciones y se rotulan `fallback` | Un demo no debe depender de la disponibilidad del modelo, ni ocultar cuándo no lo usó |
| Auditoría de clase | Tras cerrar un incidente se prueba la misma clase en el resto de la API | Una clase de defecto rara vez aparece una sola vez |
