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
2. **Desvía.** El request sospechoso se ejecuta en un clon de producción con datos sintéticos, nunca en producción. Ahí hay oráculos que miran qué hizo la aplicación: consultas SQL, archivos, procesos, red y datos de otro dueño. Si uno dispara, hay una prueba reproducible. Un falso positivo cuesta latencia, nunca un usuario bloqueado.
3. **Contiene.** De esa prueba sale una regla acotada a la ruta y el parámetro, nunca a la IP, activa en menos de dos segundos. La escribe código, no un modelo, tiene vencimiento y se borra cuando el parche queda verificado.
4. **Corrige.** Un agente confinado propone el parche. No decide: el parche solo sale si pasa cinco validaciones mecánicas, entre ellas frenar el exploit original y dejar pasar el tráfico legítimo grabado. Se despliega en canario, con rollback.
5. **Recuerda.** Con la batería de ese mismo ataque, Immune sondea el resto de la API en un entorno aislado y parchea lo que encuentre de la misma clase.

## Resultados medidos

En nuestra app de prueba (7 fallas plantadas: inyección SQL, path traversal y acceso a datos ajenos):

- 21 de 21 incidentes parchados, sin reintentos. Mediana desde el ataque confirmado: regla a los 1,9 s, parche en producción a los 24,9 s.
- Con 3 ataques, uno por clase, quedaron parchadas las 7 fallas: 4 las encontró la auditoría propia.
- Las validaciones rechazaron 15 de 15 parches defectuosos escritos a propósito y aceptaron los 7 correctos.

Datos: `docs/demo/metricas-tiempo-a-parche.json`.

Sobre software real:

- **Grafana 8.3.0 (CVE-2021-43798).** Ciclo completo sobre el binario sin modificar: regla a los 0,6 s, parche en producción a los 54 s, medido en local. Ver `labs/grafana-cve-2021-43798/`.
- **Apache HTTP Server 2.4.49.** Revisando el código, el parche propuesto se comporta igual que el oficial en 21 de 21 casos. Ver `docs/demo/anticipacion-apache-2.4.49.md`.
- **FUXA v1.2.9.** Una interfaz de operación de una planta de tratamiento de agua, protegida por Immune. La demo usa evidencia sintética, marcada como tal. Ver `docs/fuxa.md`.

Las fallas de Grafana y Apache son públicas: prueban el mecanismo, no un descubrimiento.

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

## Límites

- Lo que los oráculos no ven, el sistema no lo aprende: fallas de lógica de negocio, credenciales robadas y ataques de segundo orden quedan afuera.
- Lo que el clasificador no marca como sospechoso llega a producción.
- La auditoría propia cubre hoy tres clases: inyección SQL, path traversal y acceso a datos ajenos.
- Protege la capa HTTP. Los tiempos son de nuestra app de prueba y de un laboratorio local, no de producción.

## Más

- `docs/arquitectura.md`: el diseño.
- `contracts/README.md`: el contrato técnico del sistema.
- `docs/HANDOFF.md`: qué está verificado y qué no.
