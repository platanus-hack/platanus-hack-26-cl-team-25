# Handoff — Inmune, sistema inmunológico autónomo (team-25)

Estado al 2026-11-21. Todo el código está en `main` (commit `0fcc328`).

## 1. Qué es

Un gateway delante de una app que:

1. **Detecta** requests sospechosos y los ejecuta primero en una copia sombra instrumentada de la app (misma app, datos sintéticos).
2. **Confirma** el ataque de forma mecánica con "oráculos" (hooks en SQL, archivos, procesos, red y datos de otro dueño).
3. **Contiene** con una regla en el gateway (segundos) y **cura** con un parche de código escrito por un LLM, validado por cinco puertas mecánicas, y desplegado en blue/green (alrededor de un minuto).

Encuadre acordado para el pitch: **arquitectura de referencia open source con implementación que funciona**, y camino a producto instalable con un comando.

## 2. Documentos

| Archivo | Contenido |
|---|---|
| `docs/arquitectura.md` | Diseño v2: fallas de la v1 y cómo se resolvieron |
| `docs/plan-construccion.md` | Plan de construcción, validaciones del parche (§4), criterios de aceptación (§9), demo (§9b), PRs y vuelta a t0 (§9c), memoria y aprendizaje (§9d), límites declarados (§11) |
| `docs/plan-producto.md` | Producto: `immune init`, adaptación con LLM, oráculos fuera del proceso para cualquier lenguaje, deploy |
| `contracts/README.md` | **Contrato del sistema**: procesos, puertos, redes, protocolos. Es la fuente de verdad técnica |
| `contracts/interfaces.md` | Interfaces entre `pipeline`, `patcher` y `sim` |

## 3. Componentes

| Directorio | Qué es | Corre como |
|---|---|---|
| `victim/` | App de prueba "Tienda" (FastAPI + SQLite) con 7 bugs plantados, listados en `victim/VULNS.md` | Contenedor |
| `shadow/` | Wrapper que instrumenta la app y emite el veredicto | Dentro de cada clon |
| `gateway/` | Proxy: clasifica, detona, desvía, aplica reglas | Contenedor (8080 datos, 8081 admin) |
| `fleet/` | Único con acceso a Docker: pool de clones y blue/green | Proceso del host (8070) |
| `pipeline/` | Incidente → caso reproducible → regla → parche → 5 puertas → PR → deploy → verificación | Proceso del host |
| `patcher/` | Llama a `claude -p` confinado para escribir el parche; trae parches de respaldo | Librería |
| `dashboard/` | Bus de eventos y panel en vivo | Contenedor (8090) |
| `sim/` | Tráfico legítimo y escenarios deterministas | Proceso del host |
| `immune_contracts/` | Código compartido (tokens, gramática, protocolo, eventos) | Librería |
| `acceptance/` | Tests de aceptación por paquete | — |

## 4. Cómo correrlo

Requisitos en la VM: Docker, `.venv/`, imágenes `immune-base:1`, `immune-sidecar:1`, `immune-cbuild:1`. `install.sh` los prepara en una máquina nueva (probado desde cero en un Ubuntu 24.04 limpio; `immune doctor --prereqs` dice qué falta). `immune-cbuild:1` solo hace falta para `anticipate` (`IMMUNE_WITH_ANTICIPATE=1 ./install.sh`).

```bash
bin/immune reset                         # demo incorporado (app Tienda): vuelve a t0 y levanta todo
bin/immune up                            # levanta, o recupera lo que falte SIN volver a t0 (mantiene parches, reglas e incidentes)
bin/immune status                        # resumen de salud; sale con 1 si algo no está sano
bin/immune down
bin/immune init --project DIR --yes      # adapta el sistema a otra app (FastAPI + SQLite), ~45 s, 3 llamadas al LLM
bin/immune up   --project DIR            # levanta el stack para esa app
python -m immune.metrics --bus http://127.0.0.1:8090   # tiempos por incidente
python -m pipeline.selftest              # autotest de las validaciones
python -m anticipate run apache-httpd-2.4.49
```

- Puertos por defecto: gateway 8080, admin 8081, dashboard 8090, fleet 8070 (configurables en `.immune/config.yaml`). Todo en `127.0.0.1`.
- Toda la configuración de una app vive en `<proyecto>/.immune/` (contrato: `contracts/product.md`).
- Tests: `.venv/bin/pytest acceptance victim/tests shadow/tests gateway/tests pipeline/tests patcher/tests sim/tests dashboard/tests anticipate/tests fleet/tests immune/tests sidecar/tests -q -m "not live" -p no:cacheprovider` (507 pasan).
- El LLM usa el login de Claude Code de la máquina.
- `fleet` y `pipeline` corren supervisados como unidades de systemd del usuario (`immune-<proyecto>-fleet|pipeline`): se reinician solos y **no mueren al cerrar la terminal o la sesión del agente que los lanzó** (antes sí morían; así se cayó el stack el 21/11 a las 18:38). Logs en `runtime/logs/`.
- Qué pasa cuando algo falla, con tiempos medidos: `contracts/product.md` §11.

## 5. Qué está verificado (corrido por el orquestador, 2026-11-21)

| Cosa | Resultado |
|---|---|
| Suites completas + autotest de validaciones | 463 pasan; rechaza 15 parches inadecuados, acepta 7 |
| **Tiempo de identificado a parche en producción**, app Tienda, 7 defectos × 3 rondas, de a uno | **21/21 parchados, mediana 24,9 s** (mín 22,2, máx 31,0). Regla a los 1,9 s. Datos: `docs/demo/metricas-tiempo-a-parche.json` |
| `immune init` + `up` sobre `examples/notas` (app FastAPI ajena, sesiones opacas) | init READY en 47 s; sus 4 defectos parchados solos (22–63 s a producción) |
| Runtime genérico sobre `examples/tareas-node` (Node + Postgres, observador externo) | Stack arriba en 11 s; SQLi parchado en 37 s. Traversal e IDOR: detectados, regla y PR abierto, sin merge por falta de tráfico legítimo grabado que cubra la ruta (comportamiento diseñado). El agente constructor reportó los tres parchados con tráfico previo |
| **Memoria inmunológica**: solo 3 peticiones enviadas, una por clase | Los 7 defectos parchados; 4 hallados por auditoría propia sin que nadie los ejerciera. 23,7 s de mediana a producción |
| Anticipación sobre Apache 2.4.49 | Parche sugerido equivalente al oficial en 21/21 vectores |
| **Fallas inyectadas en vivo** con 20 req/s de tráfico legítimo: matar fleet, pipeline, supervisor, gateway, prod, clones y bus; matar pipeline al abrir un incidente; matar fleet en pleno deploy; tirar el gateway con una regla activa; release rota; LLM caído | Todo se recupera solo en 1–3 s; los incidentes interrumpidos terminan parchados; el LLM caído deja los defectos contenidos por regla y se parchan al volver. Tabla completa en `contracts/product.md` §11 |
| Entradas malformadas al gateway (cuerpo de 20 MB, URL de 100 KB, JSON inválido o muy anidado, bytes no UTF-8, 500 headers, cliente lento, 300 conexiones ociosas, 200 simultáneas) | Sin caídas ni reinicios; memoria estable (28 → 33 MB) |

## 6. Qué NO está verificado ni hecho

- **Pull requests en GitHub**: solo con `gh` simulado. Corre en modo `local`.
- **Dashboard**: visto solo en Chromium sin interfaz (capturas a 1440 px y 400 px) con los datos de una corrida terminada; falta mirarlo con un incidente en curso y en el proyector.
- (Hecho) Reintento con feedback, en vivo: un primer parche que no arreglaba nada (puesto a propósito) fue rechazado por la validación `properties`; el segundo, del LLM real con ese rechazo como contexto, pasó y llegó a producción. El rollback de un deploy roto también se probó en vivo.
- **Reinicio de la máquina**: `immune up` retoma donde quedó, pero nada lo ejecuta al arrancar.
- **Bus de eventos** (`runtime/bus/events.jsonl`): crece sin límite en disco y en memoria (probado hasta ~4.000 eventos); grabación y releases sí están acotadas.
- **Dashboard público**: los lectores sin token reciben los eventos con credenciales y rutas del host tachadas, pero los ids de sesión y de usuario siguen visibles.
- **`examples/notas`** no trae `.immune/` (lo genera `immune init`) ni base: antes correr `python scripts/init_db.py --db data/notas.db`, y fijar `ports:` si el demo incorporado está arriba.
- **Atacante simulado en bucle** para el demo: no existe; las peticiones de prueba están en `victim/VULNS.md`.
- **`immune deploy`** sobre infraestructura real: solo simulacro. Hoy `immune up` corre prod por su cuenta desde releases; falta definir el modo "gateway delante del servicio existente del cliente".
- **`install.sh`**: probado en Ubuntu 24.04 ARM64 limpio; falta x86_64, otras distros y la rama que construye las imágenes dentro del propio script.
- **`immune init` para apps genéricas** (Node, etc.): el perfil de `tareas-node` está escrito a mano.
- Runtime genérico: solo Postgres; lenguajes compilados no probados en el juez; chequeos de política sobre código no Python son léxicos.
- Revisión independiente, equipo rojo y vulnerabilidad ciega.


## 7. Decisiones tomadas

- El veredicto lo da la ejecución en la sombra, no un score. Un falso positivo cuesta latencia, no datos falsos.
- El LLM solo propone un diff; deciden validaciones mecánicas.
- Las reglas nunca bloquean por IP ni huella; fuerzan detonación y fallan cerrado solo en el punto confirmado.
- Los hooks corren solo en los clones, nunca en el proceso de producción.
- Cada corrida parte del tag de t0 en una rama propia (`run/<id>/base`); no se borran ni reabren PRs.
- Se publica solo el dashboard, nunca el gateway con la app vulnerable detrás.
- Diferencial: **memoria inmunológica** (tras curar un bug, buscar la misma clase en el resto de la app) y detección que mejora con cada veredicto.

## 8. Sugerencia del mentor: demo sobre software real previo a un parche — HECHO (Apache)

`anticipate/` (ver `anticipate/README.md`). Toma el código público de **Apache HTTP Server 2.4.49**, le pide al modelo confinado que revise el normalizador de rutas sin decirle cuál es el aviso, valida mecánicamente el parche y lo compara con el oficial de 2.4.50.

```
.venv/bin/python -m anticipate run apache-httpd-2.4.49
```

Resultado medido: 2.4.49 cumple 14/21 propiedades; el parche sugerido y el oficial, 21/21, con resultado idéntico en los 21 vectores y en la misma función. Unos 35 s. Copia del reporte: `docs/demo/anticipacion-apache-2.4.49.html`.

Es análisis de código fuente: no se levanta Apache ni se envía tráfico.

**Límite a decir:** es un defecto público y famoso; el modelo probablemente lo conocía. Demuestra el mecanismo, no descubrimiento ciego. GitLab no se hizo (Ruby, varios servicios).

## 9. Próximos pasos sugeridos, en orden

1. Correr traversal e IDOR de punta a punta en vivo y arreglar lo que aparezca.
2. Abrir el dashboard en un navegador y corregir lo visual.
3. Activar PRs en un repo de pruebas (`REPO_TARGET=scratch`) y después en el oficial.
4. Demo sobre software real: hecho para Apache (sección 8). Pendiente: un aviso posterior a la fecha de corte del modelo para una prueba ciega.
5. Memoria inmunológica (barrido de clase).
6. Completar `platanus-hack-project.jsonc`, `project-description.md` y el README de la entrega (el README pide un formato particular; leerlo antes).

## 10. Riesgos y cosas a saber

- **Cuota del LLM:** el agente de parches comparte el login con quien esté usando Claude Code en la máquina.
- **Tiempos:** medidos una sola vez, en una VM de 4 cores sin otra carga.
- **`runtime/`** no está en git; `deploy/demo.sh reset` lo regenera.
- **`deploy/demo.env`** tiene secretos de demostración sin valor real; no reutilizarlos.
- **Límites que hay que decir en el pitch:** están en `docs/plan-construccion.md` §11. El principal: los oráculos no se corrigen solos, y lo que ellos no ven, el sistema no lo aprende.
- Constructores y revisores fueron la misma familia de modelos: sus puntos ciegos están correlacionados.
