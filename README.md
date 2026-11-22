# Immune · team-25 · Platanus Hack 26: Santiago ft. Buk

**Current project logo:** project-logo.png

<img src="./project-logo.png" alt="Logo de Immune" width="200" />

Track: 🛡️ AI Safety

team-25

- Nicolás Funes ([@nicolas152](https://github.com/nicolas152))
- Bautista Silvano ([@hernei152](https://github.com/hernei152))
- Isidro Pasman ([@isidropasman](https://github.com/isidropasman))
- Uriel Gandelman ([@UriGandel](https://github.com/UriGandel))

## El problema

El software del que depende la vida de la gente no se puede corregir a la velocidad a la que hoy se lo ataca.

Atacar se volvió barato: un agente encuentra y explota una falla en horas. Corregirla sigue dependiendo de una persona, y lleva semanas. El agua, la energía y las historias clínicas corren sobre software que nadie alcanza a parchear a tiempo.

## Qué es

Immune protege infraestructura crítica frente a vulnerabilidades zero-day. Es un proxy inverso que se pone delante de la aplicación: desvía cada request sospechoso a un clon de producción con datos sintéticos y, si el ataque funciona ahí, lo contiene con una regla y despliega un parche validado, sin intervención humana.

No necesita conocer la falla de antemano. No mira cómo se ve el request: mira qué hace.

## Cómo funciona

1. **Clasifica.** Cada request se valida contra el contrato OpenAPI de la aplicación y una gramática segura por parámetro. El clasificador es determinista: no hay un modelo de lenguaje en el camino del tráfico. Lo que se sale del contrato no se bloquea, se marca como sospechoso.
2. **Desvía.** El request sospechoso se ejecuta en un clon de producción con datos sintéticos, nunca en producción. Ahí hay oráculos que miran qué hizo la aplicación: consultas SQL, archivos, procesos, red y datos de otro dueño. Si uno dispara, hay una prueba reproducible. Si ninguno dispara, el request sigue a producción: un falso positivo cuesta latencia, no un usuario bloqueado. Dos excepciones: una ruta con segmentos `..` se niega siempre, y un punto con regla activa se niega cuando el clon no llega a un veredicto.
3. **Contiene.** De esa prueba sale una regla acotada a la ruta y el parámetro, nunca a la IP. En nuestra app de prueba quedó activa a los 1,9 s de mediana. La escribe código, no un modelo, y se borra cuando el parche queda verificado.
4. **Corrige.** Un agente confinado propone el parche. No decide: el parche solo sale si pasa cinco validaciones mecánicas, entre ellas frenar el exploit original y no cambiar el comportamiento legítimo (escenarios guionados o requests grabados por el gateway). Se despliega en blue/green: antes del cambio, una parte del tráfico real pasa por la versión nueva (canario), y hay rollback automático.
5. **Recuerda.** Con la batería de ese mismo ataque, Immune sondea el resto de la API en un entorno aislado y parchea lo que encuentre de la misma clase.

El recorrido completo, con la tabla de decisiones del gateway y el estado de cada pieza (construida, parcial, no construida), está en [docs/arquitectura.md](docs/arquitectura.md).

## Resultados medidos

En nuestra app de prueba (7 fallas plantadas por el equipo: inyección SQL, path traversal y acceso a datos ajenos):

- 21 de 21 incidentes parchados, sin reintentos. Mediana desde que se abre el incidente: regla a los 1,9 s, parche en producción a los 24,9 s. Medido el 2026-11-21 en una máquina ARM64 de 4 núcleos compartida; datos en `docs/demo/metricas-tiempo-a-parche.json`. La medición es anterior a las correcciones de la auditoría del 2026-11-22 y al canario, y no se repitió.
- Con 3 ataques, uno por clase, quedaron parchadas las 7 fallas: 4 las encontró la auditoría propia. Observado una vez, sin datos crudos en el repositorio.
- Las validaciones rechazaron 15 de 15 parches defectuosos escritos a propósito y aceptaron los 7 correctos. Salida en `docs/demo/selftest-2026-11-22.txt`.

Sobre software real:

- **Grafana 8.3.0 (CVE-2021-43798).** Ciclo completo sobre la imagen oficial sin modificar: regla a los 0,6 s, parche en producción a los 54 s, medido en local en una corrida con cachés calientes, sin datos crudos en el repositorio. Ver `labs/grafana-cve-2021-43798/`.
- **Apache HTTP Server 2.4.49.** Revisando el código, el parche propuesto se comporta igual que el oficial en 21 de 21 casos escritos por el equipo, sobre la función extraída y no sobre un servidor en marcha. Ver `docs/demo/anticipacion-apache-2.4.49.md`.
- **FUXA v1.2.9.** Una interfaz de operación de una planta de tratamiento de agua, protegida por Immune. La demo usa evidencia sintética, marcada como tal. Ver `docs/fuxa.md`.
- **ScadaBR 1.2.0 (CVE-2026-8602).** Escritura de datos de sensores sin autenticación: detección en el clon, regla que solo alcanza a quien no tiene identidad y parche Java propuesto por el agente, compilado y probado en un contenedor candidato. La credencial de los dispositivos legítimos la modela el gateway. Sin cifras. Ver `labs/scadabr-cve-2026-8602/`.
- **OpenEMR 8.2.0.** Historia clínica en PHP y MariaDB, sin modificar, sobre el runtime genérico. Verificado en local por el equipo, sin datos crudos en el repositorio. Ver `docs/openemr.md`.

Las fallas de Grafana y Apache son públicas: prueban el mecanismo, no un descubrimiento.

Todas las cifras, con fecha, máquina, método y nivel de respaldo, están en [docs/resultados.md](docs/resultados.md).

## Instalar y probar

Requiere Linux con Docker Engine utilizable sin sudo, el plugin de Docker Compose, git y Python 3.12 o superior con el módulo venv.

```bash
git clone https://github.com/platanus-hack/platanus-hack-26-cl-team-25.git immune && cd immune
./install.sh                 # revisa requisitos, crea .venv, construye las imágenes y enlaza ~/.local/bin/immune
immune doctor --prereqs      # qué tiene esta máquina y qué es opcional
cd /ruta/a/tu-app && immune init && immune up
```

`install.sh` no usa sudo y se puede volver a correr. Opcionales, todos informados por `immune doctor --prereqs`:

- **Claude Code CLI** (`claude`, con sesión iniciada): los pasos con modelo de `immune init` y los parches automáticos. Sin él, `immune init --no-llm`: los ataques se detectan y se contienen con una regla, pero no se parchean.
- **GitHub CLI** (`gh`, con sesión iniciada): solo para `repo.target: github`.
- **`immune-cbuild:1`**: solo para `immune anticipate` (`IMMUNE_WITH_ANTICIPATE=1 ./install.sh`).

`immune init` cubre aplicaciones Python ASGI (FastAPI) con SQLite. Para probar sin una app propia, `immune up` desde la raíz del checkout levanta la app de prueba: la tienda queda en `http://127.0.0.1:8080` y el panel en `http://127.0.0.1:8090`. Comandos, modos, puertos, variables y recuperación: [docs/operacion.md](docs/operacion.md).

Tests, sin los que llaman al modelo (necesita Docker): `.venv/bin/pytest -q -m "not live"`. El resultado de la última ejecución está en [docs/resultados.md](docs/resultados.md#2-tests-y-autotest).

## Límites

- Lo que los oráculos no ven, el sistema no lo aprende: fallas de lógica de negocio, credenciales robadas y ataques de segundo orden quedan afuera.
- Lo que el clasificador no marca como sospechoso llega a producción.
- La auditoría propia cubre hoy tres clases: inyección SQL, path traversal y acceso a datos ajenos, y está activa por defecto solo en aplicaciones Python.
- Protege la capa HTTP. Los tiempos son de nuestra app de prueba y de un laboratorio local, no de producción.
- La validación del diff (`policy`) es una heurística sintáctica y no hay un segundo modelo revisor.
- Las fallas de la app de prueba las plantó el equipo. No hubo equipo rojo ni revisión independiente.

La lista completa, por componente, y lo que no está construido: [docs/limites.md](docs/limites.md).

## Más

| Documento | Para qué |
|---|---|
| [docs/README.md](docs/README.md) | Índice completo de la documentación |
| [docs/arquitectura.md](docs/arquitectura.md) | El diseño: cómo fluye un request y un incidente, fronteras de confianza, qué está construido |
| [docs/validaciones.md](docs/validaciones.md) | Qué garantiza y qué no cada validación del parche |
| [docs/operacion.md](docs/operacion.md) | Instalación, comandos, puertos, secretos, variables, tests, recuperación |
| [docs/resultados.md](docs/resultados.md) | Resultados medidos y su nivel de respaldo |
| [docs/limites.md](docs/limites.md) | Límites y partes no construidas |
| [docs/decisiones.md](docs/decisiones.md) | Decisiones de diseño y sus razones |
| [docs/proceso.md](docs/proceso.md) | Cómo se construyó y cómo auditarlo |
| [contracts/README.md](contracts/README.md) | El contrato técnico del sistema (en inglés) |
