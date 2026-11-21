# Plan de producto — instalable en cualquier servidor

Convierte la implementación de referencia (hoy atada a la app `victim/`) en un producto que se instala con un comando sobre una app ajena.
Complementa `docs/plan-construccion.md`; no lo reemplaza. Nada de lo de este documento está construido.

## 1. Experiencia objetivo

Un solo comando hace todo el trabajo; el usuario no corre pruebas a mano.

```
curl -fsSL <url>/install.sh | sh
cd mi-app && immune init
```

`immune init`:

1. analiza la app y genera `.immune/` (sección 3);
2. levanta un clon y **se verifica solo** (los chequeos de la sección 5 corren adentro del comando, con corrección automática por LLM);
3. detecta cómo se despliega la app hoy (Docker Compose, Kubernetes, systemd, PaaS) y **genera los artefactos de deploy** para ese entorno: `compose.immune.yaml`, manifiestos o unit files, con el gateway delante de la app;
4. termina con uno de dos resultados:
   - **Listo:** el comando exacto de deploy (`immune deploy`, o `docker compose -f … up -d`, o `kubectl apply -f …`) y qué cambia en el tráfico;
   - **Falta algo:** una lista corta y concreta de lo que no pudo resolver solo (por ejemplo, "no encontré cómo se emite el token; indicá el archivo").

Después del deploy el sistema está activo: desvío, reglas y parches como pull request. El merge automático es una opción (`immune autopatch merge`).

`immune status`, `immune report` y `immune down` son los únicos otros comandos.

## 2. Qué es genérico y qué hay que adaptar

| Pieza | Hoy | Para producto |
|---|---|---|
| Gateway, pool, ciclo de parcheo, validaciones, bus, dashboard | Genérico (usa OpenAPI) | Empaquetar como imágenes |
| Hooks (oráculos) | Python + `sqlite3` | Un **adaptador por runtime** |
| Perfil de la app | Escrito a mano | **Generado con LLM**, revisado por humano |
| Datos sombra | Seed propio de la víctima | **Generador genérico** a partir del esquema |
| Restauración del clon | Backup de SQLite | Un **driver por base de datos** |
| Arranque de prod y clones | `fleet` asume `victim/` | Leer de `.immune/config.yaml` |

## 3. `.immune/` (lo que genera `init`)

```
.immune/config.yaml     runtime, comando de arranque, puerto, health, base, tests, repo
.immune/openapi.yaml    copiado, generado por el framework, o inferido
.immune/profile.*       adaptador de la app (ver 4)
.immune/shadow/         esquema, clasificación de columnas, receta del seed sintético
.immune/report.md       qué se detectó, qué se asumió, qué requiere revisión
```

Todo es texto versionable. El cliente lo revisa y lo commitea.

## 4. Pasos de `immune init` y dónde entra el LLM

| # | Paso | Cómo | LLM |
|---|---|---|---|
| 1 | Detectar runtime, framework, comando de arranque, puerto | Heurísticas sobre `pyproject`, `package.json`, Dockerfile | Solo si las heurísticas no alcanzan |
| 2 | Obtener el OpenAPI | FastAPI: se pide a la app. Express: buscar spec existente; si no hay, inferir de las rutas | **Sí**, para inferir rutas y esquemas en Node |
| 3 | Detectar base y esquema | Introspección de la base o de las migraciones | No |
| 4 | Clasificar columnas: públicas, privadas, secretas; y de quién es cada tabla | Nombres, tipos, claves foráneas | **Sí**: propone, con justificación por columna |
| 5 | Perfil: cómo se autentica, cómo crear un usuario, cómo emitir un token, rutas públicas, raíces de archivos | Lectura del código de auth | **Sí**: genera el adaptador |
| 6 | Seed sombra: mismos ids y relaciones, contenido sintético con marcadores por dueño | Generador genérico guiado por el paso 4 | No (opcional para dar realismo) |
| 7 | Marcar `x-owner-scoped` y `x-sensitive` en el OpenAPI | Cruce de rutas con tablas con dueño | **Sí** |
| 8 | Detectar suite de tests y cómo correrla | Heurísticas | No |
| 9 | **Verificación mecánica** de todo lo anterior | Ver 5 | No |

Regla: el LLM propone archivos; nunca se confía en ellos sin el paso 9. Corre con el mismo confinamiento que el agente de parches (solo lectura del repo, escritura solo en `.immune/`).

## 5. Verificación de la adaptación (`immune doctor`)

Cada punto es un sí/no; si falla, `init` vuelve a pedirle al LLM con el error, hasta 3 veces, y después lo deja en `report.md` para un humano.

1. La app arranca en un clon con los hooks cargados y responde el health.
2. El perfil crea un usuario y emite un token que la app acepta.
3. Un request legítimo por ruta del OpenAPI da veredicto `limpio`.
4. **Canarios sintéticos:** se inyecta a propósito, en el clon, una consulta concatenada, una lectura fuera de raíz y una lectura de fila ajena; cada oráculo tiene que disparar. Prueba que los hooks ven ese stack.
5. La restauración del clon vuelve al estado semilla.
6. Ningún dato real aparece en la base sombra (comparación contra una muestra de prod).
7. La suite de tests pasa dentro del runner aislado. Si no hay tests: el modo máximo es `autopatch pr`.

## 6. Adaptadores

**Runtime (hooks):** misma lista de eventos y mismo protocolo HTTP que hoy.

| Runtime | Mecanismo | Drivers iniciales |
|---|---|---|
| Python (FastAPI, Starlette, Flask) | Wrapper ASGI/WSGI + audit hooks (existe) | `sqlite3`, `psycopg`, `asyncpg`, SQLAlchemy sobre ellos |
| Node (Express, Fastify) | `node --require` que envuelve `http`, `fs`, `child_process`, `net` y el driver | `pg`, `mysql2`, `better-sqlite3` |

**Base de datos (seed, snapshot, restauración):**

| Base | Restauración del clon |
|---|---|
| SQLite | API de backup (existe) |
| Postgres | Base plantilla por clon (`CREATE DATABASE … TEMPLATE`) |
| MySQL | Volcado en memoria; más lento, se declara |

**Fuera de alcance de la v1:** Redis, colas, almacenamiento de objetos, llamadas a terceros y apps de varios servicios. `init` los detecta y los lista en `report.md` como no cubiertos.

## 6b. Oráculos fuera del proceso (cualquier lenguaje)

Para no escribir hooks por lenguaje (.NET, Go, Rust, Java, PHP…), los oráculos salen del proceso de la app y pasan a un **sidecar del clon**. La app corre sin modificar, en su propia imagen.

| Oráculo | Dónde se observa | Depende del lenguaje |
|---|---|---|
| SQL | **Proxy del protocolo de la base** entre la app y su base sombra (Postgres, MySQL). Ve la consulta final y aplica el mismo chequeo de valor de entrada que cruza tokens | No |
| Archivo, proceso, red | Syscalls del contenedor del clon (eBPF o seccomp-notify): `openat`, `execve`, `connect` | No |
| Dueño | Cuerpo de la respuesta, en el sidecar (marcadores) | No |
| Atribución al request | Un request a la vez por clon | No |
| Restauración | Driver de base (plantilla Postgres, etc.) | No |

Lo que se pierde: el **stack con archivo y línea**, que hoy guía al agente de parches. Reemplazos, en orden de preferencia:

1. Agente opcional por runtime que solo aporta el stack (Python y Node primero; OpenTelemetry donde exista).
2. Sin agente: el LLM localiza el punto a partir de la ruta, el parámetro y la consulta o ruta de archivo observada. La validación sigue siendo mecánica, así que un error de localización se traduce en un parche rechazado, no en uno malo.

Límites: bases embebidas en el proceso (SQLite) no pasan por el proxy y necesitan hook de runtime; consultas preparadas del lado del servidor se evalúan sobre el texto de la sentencia y sus parámetros; binarios estáticos (Go, Rust) funcionan igual porque se observa el kernel, no la librería.

Requisitos del host: Linux con eBPF habilitado o seccomp-notify, y permiso para lanzar contenedores con esos privilegios **solo en el sidecar**.

Los tests y el build por lenguaje (`dotnet test`, `go test`, `cargo test`) los declara `.immune/config.yaml`; `init` los detecta.

## 6c. Deploy en producción

Los hooks y oráculos corren **solo en los clones**, nunca en el proceso de prod. En prod se agrega el gateway delante de la app y el pool de clones al lado.

`immune deploy` aplica los artefactos generados por `init`. Si el entorno no se puede automatizar (PaaS sin acceso, balanceador externo), `init` escribe en `.immune/DEPLOY.md` los pasos exactos para ese entorno.

Protecciones que no requieren acción del usuario: fail-open del gateway, verificación de salud antes de tomar tráfico, y rollback automático del deploy si suben los errores.

## 7. Modos y seguridad por defecto

| Modo | Qué hace |
|---|---|
| `observe` (opcional) | Clasifica y detona en paralelo; **nunca** cambia la respuesta al cliente |
| `enforce` (por defecto tras el deploy) | Desvío, cautiverio y reglas |
| `autopatch pr` | Abre el PR con evidencia y validaciones; no hace merge |
| `autopatch merge` | Merge y deploy automáticos; requiere tests y activación explícita |

El producto corre entero en la infraestructura del cliente. Lo único que sale es lo que el cliente configure como proveedor de LLM.

## 8. Paquetes de trabajo

| PP | Qué | Depende de |
|---|---|---|
| 1 | Desacoplar de `victim/`: `fleet`, `pipeline` y `shadow` leen `.immune/config.yaml`; la víctima pasa a ser "una app más" con su propio `.immune/` | Ciclo de parcheo terminado |
| 2 | CLI `immune` (`init`, `up`, `doctor`, `report`, `enforce`, `autopatch`, `down`) e `install.sh`; imágenes publicadas | PP1 |
| 3 | `init` determinista: pasos 1, 3, 6, 8 | PP1 |
| 4 | `init` con LLM: pasos 2, 4, 5, 7, con el lazo de corrección contra `doctor` | PP3, PP5 |
| 5 | `doctor`: los siete chequeos, incluidos los canarios sintéticos | PP1 |
| 6 | Modo `observe` en el gateway y `immune report` | PP1 |
| 7 | Driver Postgres + hooks `psycopg`/`asyncpg`/SQLAlchemy | PP1 |
| 8 | Adaptador Node: hooks, wrapper, `pg` | PP1, PP5 |
| 9 | Corpus de validación: 3 apps que no escribimos (FastAPI+SQLite, FastAPI+Postgres, Express+Postgres) con bugs conocidos | — |

Orden: PP1 → PP5 y PP3 en paralelo → PP2, PP4, PP6 → PP7 → PP8. PP9 se prepara desde el inicio y es el criterio de aceptación de todo.

## 9. Criterios de aceptación

Sobre cada app del corpus, sin tocar su código a mano:

1. `immune init` termina y `immune doctor` da todo en verde, o `report.md` dice exactamente qué falta.
2. En `observe`, el tráfico legítimo de la app tiene menos de un umbral fijado de detonaciones con veredicto de ataque (objetivo: cero).
3. En `enforce`, los bugs conocidos de la app se detectan y se contienen.
4. En `autopatch pr`, se abre un PR que pasa las validaciones para al menos un bug por clase.
5. `immune down` deja la máquina como estaba.

## 10. Para el hackathon

Recorte mínimo que sostiene el pitch de producto: **PP1 + PP5 + PP3/PP4 solo para FastAPI con SQLite + una app del corpus**. Muestra `immune init` adaptando en vivo una app que no escribimos. Node y Postgres quedan como hoja de ruta.

## 11. Riesgos

- **El perfil generado puede estar mal de forma silenciosa** (por ejemplo, marcar como pública una ruta privada). Mitigación: los chequeos de `doctor` y la revisión humana de `report.md`; no hay mitigación completa.
- **Apps sin OpenAPI ni tests** reducen mucho el valor: sin spec la clasificación es más débil, y sin tests no hay parche automático.
- **Postgres cambia los tiempos** de restauración; no está medido.
- **Clasificar mal una columna** puede llevar datos reales a la sombra. El chequeo 6 lo cubre por muestreo, no por garantía.
