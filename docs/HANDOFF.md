# Handoff — Winnie Pooh, sistema inmunológico autónomo (team-25)

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

Requisitos ya instalados en la VM: Docker, `.venv/` con dependencias fijadas, imagen `immune-base:1`.

```bash
deploy/demo.sh reset     # vuelve todo a t0 y levanta el sistema completo
deploy/demo.sh status
deploy/demo.sh down
```

- Dashboard: `http://127.0.0.1:8090` (solo local; para verlo desde afuera hace falta un túnel SSH).
- Tráfico legítimo: `.venv/bin/python -m sim.legit --base http://127.0.0.1:8080 --duration 60`
- Autotest de las validaciones: `.venv/bin/python -m pipeline.selftest`
- Tests: `.venv/bin/pytest acceptance victim/tests shadow/tests gateway/tests pipeline/tests sim/tests dashboard/tests -q`
- Logs de procesos del host: `runtime/logs/`.

El LLM se usa con el login de Claude Code de la máquina. El proxy del hackathon está configurado en `.claude/settings.local.json` (no está en git; cada integrante pone su propio token).

## 5. Qué está verificado

| Cosa | Estado |
|---|---|
| Tests de aceptación: víctima 13, oráculos 18, gateway 26 | Pasan |
| Autotest de validaciones: rechaza 15 parches inadecuados y acepta 7 correctos | Pasa |
| Detección en vivo de las tres clases (SQLi, path traversal, IDOR) con desvío a la sombra | Verificado una vez |
| Ciclo completo en vivo para **SQLi**: regla a los 15 s, parche del LLM, 5 puertas, deploy y verificación en 60 s | Verificado una vez |
| Tráfico legítimo de 20 s contra el sistema: cero violaciones | Verificado por el agente constructor |

## 6. Qué NO está verificado ni hecho

- Ciclo completo en vivo para **traversal e IDOR**.
- **Pull requests en GitHub**: el código existe (`REPO_TARGET=scratch|official`) pero solo se probó con `gh` simulado. Hoy corre en modo `local`.
- **Dashboard**: nunca se vio en un navegador.
- **Rollback** de un deploy roto y reintento del parche con feedback real: sin probar en vivo.
- **Bot atacante** en bucle para el demo: no existe. Los siete requests de prueba están en `victim/VULNS.md`.
- Revisión independiente de `shadow/`, `gateway/` y `pipeline/`, y pasada de equipo rojo.
- Vulnerabilidad ciega (un bug que ningún constructor vio).
- Memoria inmunológica y aprendizaje (§9d del plan): solo diseño.
- Producto (`immune init`, otros lenguajes): solo diseño.

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
