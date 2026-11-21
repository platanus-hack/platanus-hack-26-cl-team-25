# Plan de construcción con subagentes — v2

Implementa `docs/arquitectura.md` como demo de punta a punta en un solo host.
Orquesta Fable; cada subagente construye un paquete con dueño único.

Esta versión incorpora dos revisiones independientes del borrador (una de integración, una adversarial).
La sección 10 lista qué cambió y por qué. Lo marcado **[verificado por el revisor]** lo comprobó el revisor ejecutando pruebas en este host; no lo repetí yo.

## 0. Restricciones del host

- VM ARM64, 4 cores, 23 GB RAM, 73 GB libres. Sin KVM.
- Python 3.12 y Node 22. **Docker no está instalado** (hay sudo; `docker.io` 29.1 por apt).
- `python3 -m venv` falla porque falta `ensurepip`; hay que instalar `python3.12-venv`. **[verificado por el revisor]**
- El firewall del host rechaza tráfico de contenedor a host, y `169.254.169.254` es la metadata **real** de Oracle. **[verificado por el revisor]**
- Caddy ya usa :443 y :8443 en Tailscale. No se toca.
- LLM: solo el login de Claude Code a través del proxy del hackathon. El agente de parches en runtime es `claude -p`, y comparte cuota con los agentes constructores.

## 1. Decisiones técnicas

| Tema | Decisión |
|---|---|
| Stack | Python 3.12 en todo. Un venv compartido con versiones fijadas, creado por Fable; los agentes no instalan paquetes |
| Víctima | FastAPI + `sqlite3` crudo y síncrono, sin ORM ni hilos propios. Todo el estado mutable vive en SQLite; el sistema de archivos es de solo lectura. Tokens de sesión sin estado |
| Red | Todo en contenedores. Prod y clones en redes `internal` sin salida. El gateway es el único con puerto publicado. Los clones no tienen ruta al gestor de contenedores ni a ninguna API de administración |
| Clones | Contenedores detrás de `SandboxDriver`. **Un request a la vez por clon**: la atribución de eventos es por clon, no por contexto |
| Build sombra | El mismo código de la víctima lanzado con un wrapper que instala los oráculos. No se edita la víctima |
| Datos sombra | Mismo esqueleto de claves que prod (ids y dueños), contenido sintético, datos públicos idénticos. Cada campo privado sintético lleva un **marcador por dueño** |
| Identidad | El gateway valida el token de prod e inyecta el `user_id` al clon por un header interno. El wrapper crea al usuario si no existe. Prod y sombra **no** comparten secreto |
| Veredicto | Tres valores: `limpio`, `oráculo`, `no_concluyente`. El gateway espera el cuerpo completo y una confirmación explícita del clon ("terminado, N eventos"). Sin confirmación = `no_concluyente` |
| Control del clon | Sin puerto de control. Modo (L1/L2) e identidad viajan en headers internos que solo el gateway puede poner; los entrantes del cliente se eliminan. Los eventos salen a un colector de solo escritura, firmados por clon |
| Estado | L1 se restaura a la semilla después de cada request. L2 guarda el estado previo a cada request. Siempre con la API de backup de SQLite, nunca copiando el archivo |
| Reglas | Marcan un punto **confirmado vulnerable** (ruta + parámetro). Efectos: detonar todo lo que no cumpla la gramática segura, también para identidades confiables; y si no hay clon o el veredicto es `no_concluyente`, **no** se reenvía a prod |
| Falla | Fail-open para tráfico sin señal. Fail-closed para lo que coincide con una regla activa o tiene señal alta: recibe una respuesta genérica, nunca prod |
| Cautiverio | Solo sesiones con clave reutilizable (token, o una cookie que pone el gateway). Nunca por IP. Un anónimo de un disparo recibe la respuesta del clon y el clon se restaura. Tiene TTL, y si el pool se llena se desaloja al más viejo |
| Identidad confiable | Cuentas de la semilla = confiables; cuentas creadas después = no confiables. Si un oráculo dispara para una confiable, no se le sirven datos sintéticos: recibe una negativa genérica |
| Despliegue | Sin `docker build`: el código se monta de solo lectura desde `releases/<sha>/`. Green arranca con el release nuevo, pasa el health check, el gateway drena y cambia de upstream. La base de prod está en un directorio compartido. Los parches no pueden cambiar el esquema |
| Sombra tras el parche | Los clones L1 nuevos corren el release parchado; los cautivos conservan el suyo hasta el TTL. La regla caduca |
| Agente de parches | `claude -p` en el host, solo con `Read` y `Edit`, en una copia temporal que contiene solo `victim/`, con reglas que le niegan leer fuera de ella. Su única salida aceptada es el diff de esa copia |

## 2. Detección (etapa 1) en el gateway

Un request es **dudoso**, y se detona, si cumple cualquiera de estas:

- algún parámetro se sale de la gramática segura por defecto (caracteres fuera de un conjunto conservador), viola el esquema, o está duplicado;
- la ruta es de dueño (`/orders/{id}`, `/invoices/{id}`) y la identidad no es confiable;
- coincide con una regla activa;
- la sesión muestra enumeración.

Es **evidencia directa** (captura sin detonar) un id canario de prod o un honeytoken.
Las rutas de escáner conocidas reciben respuesta procedural (L0). Una ruta inexistente cualquiera recibe el 404 real.
El gateway reenvía a prod exactamente los mismos bytes que detonó.

## 3. Oráculos (wrapper sombra)

| Oráculo | Dispara cuando | No dispara cuando |
|---|---|---|
| SQL | un valor de entrada presente en la query ejecutada abarca más de un token o toca un comentario | la query da error de sintaxis (se registra, no captura); `O'Brien` en una query parametrizada |
| Archivo | se abre una ruta resuelta fuera de las raíces permitidas | la ruta está en la lista aprendida en el precalentamiento (`/etc/mime.types`, imports) |
| Proceso | aparece un proceso hijo | — |
| Red | hay una conexión saliente | es el envío de eventos del propio wrapper |
| Dueño | la respuesta contiene un marcador de otro dueño y quien pide no es admin | login, registro, datos públicos |

El oráculo de dueño se juzga sobre el cuerpo de la respuesta, así que cubre filas, archivos y volcados por SQLi.

## 4. Validación del parche

El diff solo se despliega si pasa todo esto, en un runner sin red:

1. **Política sobre el diff** (mecánica): solo archivos de `victim/app/`; sin imports nuevos; sin lecturas nuevas de atributos del request; sin comparaciones contra literales nuevos; sin quitar chequeos de autenticación; sin cadenas de alta entropía; tamaño acotado.
2. **Propiedades positivas por clase**, no "el PoC falla":
   - SQLi: la estructura de la query no cambia bajo N entradas con metacaracteres, y `O'Brien` hace ida y vuelta.
   - Traversal: toda apertura queda bajo la raíz, y los nombres legítimos con puntos funcionan.
   - IDOR: matriz identidad × recurso; el dueño recibe 200 y el ajeno 403 o 404.
3. **PoC y variantes**: solo cuentan las variantes que disparan el oráculo en el código sin parchar; ninguna puede dispararlo en el parchado.
4. **Suite de tests** de la víctima.
5. **Escenarios legítimos**: mismas respuestas antes y después, con reloj e ids fijos. Si ningún escenario cubre el endpoint parchado, no se despliega.

Además:

- **Autotest de las puertas:** un set fijo de parches malos (lista negra de `'`, caso especial del id del PoC, puerta trasera por header, endpoint borrado) tiene que ser rechazado. Corre en CI y se muestra en el demo.
- **Reintentos:** hasta N, con la salida de las puertas como feedback. Estado final posible: "sin parche; la regla sigue activa".
- **Plan B:** un parche pregrabado por bug, por si el proxy o la cuota fallan. En el demo se rotula como tal.
- La evidencia que recibe el agente contiene texto del atacante. La defensa contra la inyección de prompt son estas puertas, no el aislamiento del texto.

## 5. Paquetes de trabajo

Cada paquete tiene un directorio y un worktree propios. Fable escribe los contratos y los tests de aceptación de cada paquete **antes** de lanzarlo; los agentes no pueden modificarlos.

| WP | Directorio | Qué construye | Modelo |
|---|---|---|---|
| 0 | `contracts/`, `deploy/`, `acceptance/`, `e2e/` | Ver sección 6 | **Fable** |
| 1 | `victim/` | Tienda: usuarios, productos, órdenes, facturas. SQLi en búsqueda, traversal en descarga, IDOR en órdenes. Suite pytest. Semillas prod y sombra con el mismo esqueleto y marcadores | Sonnet |
| 2 | `shadow/` | Wrapper, los cinco oráculos, restauración y estado previo con la API de backup, envío firmado de eventos, creación perezosa de usuarios | Opus |
| 3 | `gateway/` | Proxy, etapa 1, tres caminos, espera del veredicto, sticky por token o cookie, inyección de identidad, limpieza de headers internos, L0, grabación, reglas, fail-closed acotado, cambio de upstream con drenaje | Opus |
| 4 | `containers/` | Único servicio con el socket de Docker: pool L1/L2 con desalojo y topes, y blue/green con health check y rollback | Sonnet |
| 5 | `pipeline/` | Orquestación del ciclo (evento → PoC → regla → parche → puertas → deploy), runner sin red, las cinco puertas, autotest con parches malos | Opus |
| 6 | `patcher/` | Invocación restringida de `claude -p`, generador de variantes (mutadores primero), regla candidata, plan B | Opus |
| 7 | `dashboard/` | Colector de eventos (firma verificada), SSE, línea de tiempo. Escapa todo payload | Sonnet |
| 8 | `sim/` | Bot atacante por fases; tráfico legítimo **difícil** (apóstrofes, rutas mal escritas, paginación rápida, mismo origen que el atacante) | Sonnet |

## 6. WP0: lo que hace Fable antes de lanzar a nadie

1. Instalar Docker y `python3.12-venv`; dar acceso al socket a la sesión actual; **comprobar desde un subagente** que `docker run` funciona sin sudo.
2. Venv compartido con versiones fijadas.
3. Compose con las redes internas y regla que bloquea `169.254.0.0/16`.
4. Contratos:
   - `openapi.yaml` de la víctima, esquema de autenticación y `canaries.json`;
   - eventos del bus y evento de oráculo;
   - headers internos, confirmación de fin de request y veredicto de tres valores;
   - asignación de clones: quién adquiere, restaura, promueve y desaloja, con timeouts;
   - formato de grabación de requests;
   - regla, con **una sola implementación compartida** del comparador de gramática;
   - PoC: estado de partida + requests + oráculo esperado;
   - API en proceso del wrapper sombra, que el runner usa como juez;
   - endpoints de observación para e2e (sesiones cautivas, log de acceso de prod por id de request).
5. **App fixture** de unas 100 líneas (`sqlite3` crudo, `FileResponse`, un SQLi) para que WP2, WP3 y WP5 no esperen a la víctima real.
6. Tests de aceptación por paquete y tests e2e, que arrancan fallando.
7. `make demo-reset` idempotente.

Si a un agente le falta algo del contrato, se detiene y lo reporta; no improvisa. Si un contrato cambia, Fable avisa a los paquetes afectados.

## 7. Olas

Como mucho cinco agentes a la vez, por los 4 cores.

- **Ola 0 — Fable:** WP0.
- **Ola 1 — corte vertical de SQLi:** los ocho paquetes construyen primero solo lo necesario para un SQLi de punta a punta. WP1, WP2, WP3, WP4 y WP7 arrancan juntos; WP5, WP6 y WP8 entran cuando se libera un lugar.
- **Hito 1 — Fable:** integrar y pasar el e2e de SQLi. Primera pasada del equipo rojo, de caja blanca.
- **Ola 2:** traversal, IDOR, reglas con fail-closed, desalojo, blue/green completo, tráfico legítimo difícil. Correcciones del equipo rojo.
- **Ola 3 — Fable:** e2e completo, segunda pasada del equipo rojo, **vulnerabilidad ciega**, ensayo con tiempos medidos.

**Vulnerabilidad ciega:** un agente aparte planta un cuarto bug de una clase cubierta, que ningún constructor vio. El ciclo completo se corre contra él sin tocar el sistema.

## 8. Protocolo de revisión

1. **Aceptación:** Fable corre los tests de aceptación que escribió. El informe del agente no cuenta como evidencia.
2. **Revisión independiente** de WP2, WP3 y WP5: un agente nuevo, de modelo distinto al constructor, que recibe código y contrato pero no el informe.
3. **Corrección:** los hallazgos vuelven al mismo constructor. Dos rondas como máximo; después corrige Fable.
4. **Merge** del worktree, hecho por Fable, solo después de 1–3.
5. **Equipo rojo** (Opus, caja blanca, dos pasadas). Cada hallazgo se convierte en un test e2e. Objetivos:
   - distinguir sombra de prod;
   - explotar prod sin detección, incluyendo divergencia de estado y diferencial de parseo entre gateway y app;
   - agotar el pool y después explotar;
   - dejar cautivo a un usuario legítimo;
   - inducir una regla o un parche dañino con inyección de prompt;
   - alcanzar el gestor de contenedores o el bus desde un clon;
   - falsificar headers internos;
   - sacar un secreto canario del host a través del diff;
   - XSS en el dashboard.

Límite declarado: constructores, revisores, defensor y equipo rojo son la misma familia de modelos, así que sus puntos ciegos están correlacionados.

## 9. Criterios de aceptación de punta a punta

Con tráfico legítimo difícil corriendo todo el tiempo, y repetido N veces seguidas desde `make demo-reset`:

1. **Control negativo:** con el sistema en modo paso directo, los tres exploits funcionan contra prod.
2. **SQLi de un disparo:** el id del request no aparece en el log de acceso de prod, y la respuesta contiene marcadores sintéticos.
3. **Traversal:** igual.
4. **IDOR** con una cuenta creada después de la semilla: cero filas reales de terceros servidas antes de la captura, para objetos de la semilla.
5. **Regla:** con el pool agotado, un exploit sobre el punto con regla activa no llega a prod.
6. **Puertas:** el set de parches malos es rechazado.
7. **Parche:** una orden creada antes del deploy se lee después; cero errores para el tráfico legítimo durante el cambio.
8. **Curado:** el exploit directo contra prod, sin gateway, falla. Por el gateway, se reenvía a prod, no dispara ningún oráculo y la respuesta es inocua.
9. **Rollback:** un release roto a propósito se revierte solo.
10. **Legítimos:** ninguna respuesta al tráfico legítimo contiene un marcador sintético ni un header interno.
11. **Control caído:** prod sigue sirviendo; lo que coincide con una regla activa no llega a prod.
12. **Tiempos medidos** y publicados: a la regla, al parche, y p95 de requests limpios y dudosos. Sin umbrales de aceptación, por la contención de CPU.

## 9b. Lo que se ve en el demo

Objetivo: una app falsa vulnerable que **se va endureciendo sola, de verdad**, a la vista.

- **Varios bugs, no tres:** la víctima trae 6–8 vulnerabilidades repartidas en las tres clases (por ejemplo, SQLi en búsqueda y en login, traversal en dos descargas, IDOR en órdenes, facturas y perfil). Así la mejora se ve como una progresión.
- **Bot atacante en bucle:** recorre todos los exploits una y otra vez. Cada vuelta, menos funcionan.
- **Marcador en el dashboard:** vulnerabilidades abiertas / contenidas por regla / curadas por parche, con el tiempo de cada una.
- **Por cada bug, la secuencia completa:** request del atacante → oráculo que disparó → regla → diff real que escribió el agente → resultado de cada puerta → deploy → el mismo exploit fallando contra prod.
- **Código en vivo:** el diff aplicado se muestra tal cual, y el repositorio de la víctima queda con un commit por parche.
- **Sin atajos:** los parches se generan en vivo. El plan B pregrabado solo se usa si el proxy del LLM se cae, y se anuncia.
- **Prueba de que no es montaje:** la vulnerabilidad ciega, y una puerta rechazando un parche malo.

## 9c. Parches como pull requests y vuelta a t0

- **t0 es el tag `victim-t0`.** `main` nunca recibe parches.
- **Cada corrida tiene un id** y una rama base creada desde el tag (`run/<id>/base`). Los PRs de la corrida apuntan a esa rama, con ramas `run/<id>/fix-<bug>` y etiqueta `run-<id>`.
- **`make demo-reset`** restaura contenedores, bases, reglas y crea la rama base de una corrida nueva. No se borra ni se reabre ningún PR.
- **Por cada bug:** rama → PR con la evidencia (request, oráculo, archivo y línea, PoC) → cada puerta publicada como check → merge automático en verde → deploy → comentario final con tiempos.
- **Las puertas corren en el runner local** y reportan a GitHub. No se usa GitHub Actions.
- **El agente no toca GitHub:** produce un diff; el ciclo de parcheo crea la rama y el PR después de la política sobre el diff.
- **Interfaz `RepoTarget`** con tres destinos elegidos por configuración:
  - `local`: repo git en la máquina, sin GitHub. Es el de desarrollo y tests.
  - `scratch`: repo personal privado y descartable, para ensayar la integración.
  - `official`: el repo del hackathon, solo para el ensayo final y el demo.
- Si GitHub falla, el ciclo sigue en local y el dashboard lo muestra igual.

## 10. Qué cambió respecto del borrador

| Problema encontrado | Cambio |
|---|---|
| El header de veredicto sale antes de que `FileResponse` abra el archivo: el traversal llegaba a prod **[verificado por el revisor]** | Confirmación explícita después del cuerpo completo |
| Copiar el archivo SQLite con la app corriendo da una base vacía **[verificado por el revisor]** | API de backup sobre la conexión viva |
| El oráculo SQL por estructura dispara con `O'Brien` y no ve `a'--` **[verificado por el revisor]** | Oráculo por valor de entrada que cruza tokens; `O'Brien` es test de aceptación |
| Una cuenta creada en prod no existe en la sombra: la detonación da 401 y el exploit se reenvía a prod | Identidad inyectada, usuario creado al vuelo, veredicto `no_concluyente` |
| Cinco requests agotan el pool y el sexto va a prod | Cautiverio solo con clave de sesión, desalojo, fail-closed acotado |
| Con sticky por IP, el tráfico legítimo del demo quedaba cautivo | Clave por token o cookie; TTL |
| Blue/green perdía las órdenes creadas después de la semilla | Base de prod en directorio compartido |
| "El PoC falla y los tests pasan" lo cumple una lista negra o una puerta trasera | Propiedades positivas, política sobre el diff, autotest con parches malos |
| Los clones tenían ruta al servicio con el socket de Docker | Redes internas, gestor de contenedores aislado, sin puerto de control en el clon |
| Un SSRF desde un contenedor podía pedir credenciales reales de Oracle | SSRF fuera del demo; bloqueo de `169.254.0.0/16` |
| El criterio "el exploit falla tras el parche" pasaba aunque el parche no sirviera | Se mide directo contra prod, más control negativo |
| La regla `detonar` no hacía nada que no pasara ya | La regla ahora agrega fail-closed y alcanza a identidades confiables |
| El oráculo de dueño por filas leídas disparaba en el login | Marcadores por dueño en la respuesta |
| Tres bugs de manual escritos por los mismos modelos parecen montaje | Vulnerabilidad ciega y rechazo de un parche malo en vivo |
| WP5 era demasiado grande y WP2 esperaba sin necesidad | Paquetes partidos, app fixture, corte vertical de SQLi primero |
| Agentes compartiendo árbol, pip y daemon de Docker | Worktree por paquete, venv fijo, nombres de proyecto por paquete |

## 11. Recortes y límites declarados

- **Fuera del demo:** SSRF e internet falso, confianza de identidad graduada, sincronización del esqueleto de claves, revisor LLM en runtime, vista doble del dashboard.
- **Se corta primero si falta tiempo:** variantes por LLM, heurística de enumeración, L0.
- **Límites que se dicen en el pitch:**
  - objetos creados después de la semilla no existen en la sombra, así que un IDOR sobre ellos puede llegar a prod;
  - IDOR de escritura, ataques de segundo orden y lógica de negocio no disparan ningún oráculo;
  - un atacante con ejecución de código dentro del clon puede adulterar sus propios eventos;
  - la detonación agrega latencia medible;
  - sin control, lo que no coincide con una regla queda sin protección.

## 12. Costo y decisiones abiertas

- Unas 14 corridas de agente (8 constructores, 3 revisores, 2 pasadas de equipo rojo, 1 para la vulnerabilidad ciega), más las rondas de corrección. No hay estimación de tiempo medida.
- **URL pública:** se publica solo el dashboard de lectura, nunca el gateway. Falta elegir el medio (túnel de Cloudflare o Tailscale Funnel en el puerto 10000).
- **Modelo del agente de parches:** se mide Sonnet contra Opus en el hito 1.
