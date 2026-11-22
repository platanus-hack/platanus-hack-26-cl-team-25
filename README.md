# Immune · team-25 · Platanus Hack 26: Santiago ft. Buk

<img src="./project-logo.png" alt="Logo de Immune" width="200" />

Track: 🛡️ AI Safety

team-25

- Nicolás Funes ([@nicolas152](https://github.com/nicolas152))
- Bautista Silvano ([@hernei152](https://github.com/hernei152))
- Isidro Pasman ([@isidropasman](https://github.com/isidropasman))
- Uriel Gandelman ([@UriGandel](https://github.com/UriGandel))

## Qué es

Un sistema inmunológico para tu app. Immune es un proxy inverso que ejecuta cada request sospechoso primero en una copia aislada de la app, con datos sintéticos. Si ahí el ataque funciona, lo contiene con una regla y despliega un parche validado, sin intervención humana.

## Cómo funciona

1. **Detecta.** El gateway compara cada parámetro con el esquema de la app y una gramática segura. Lo que se sale va a un clon, no a producción.
2. **Confirma.** Cinco oráculos deterministas miran qué hizo el clon: consulta SQL, archivos, procesos, red y datos de otro dueño. El veredicto lo da la ejecución, no un puntaje. Un falso positivo cuesta latencia, nunca un cliente bloqueado.
3. **Contiene.** Una regla acotada a la ruta y el parámetro, nunca a la IP. El atacante recibe la respuesta del clon y sigue ahí.
4. **Cura.** Un LLM confinado propone un diff. No decide: el parche solo sale si pasa cinco validaciones mecánicas, y se despliega en blue/green con rollback.
5. **Recuerda.** Al cerrar el incidente, prueba esa misma clase de falla en el resto de la app y parchea lo que encuentre.

## Resultados medidos

En nuestra app de prueba (7 fallas plantadas: inyección SQL, path traversal y acceso a datos ajenos):

- 21 de 21 incidentes parchados, sin reintentos. Mediana desde el ataque confirmado: regla a los 1,9 s, parche en producción a los 24,9 s.
- Con 3 ataques, uno por clase, quedaron parchadas las 7 fallas: 4 las encontró la auditoría propia.
- Las validaciones rechazaron 15 de 15 parches defectuosos escritos a propósito y aceptaron los 7 correctos.
- Sobre el código de Apache HTTP Server 2.4.49, el parche propuesto se comporta igual que el oficial en 21 de 21 casos. Es una falla pública: prueba el mecanismo, no un descubrimiento.

Datos: `docs/demo/metricas-tiempo-a-parche.json`.

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

- Lo que los oráculos no ven, el sistema no lo aprende: fallas de lógica de negocio y ataques de segundo orden quedan afuera.
- Lo que el gateway no marca como sospechoso llega a producción.
- Protege la capa HTTP. Los tiempos son de nuestra app de prueba, no de producción.

## Más

- `docs/arquitectura.md`: el diseño.
- `contracts/README.md`: el contrato técnico del sistema.
- `docs/HANDOFF.md`: qué está verificado y qué no.
