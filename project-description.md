# Inmune

**Un sistema inmunológico para tu app.** Ejecuta cada request sospechoso en una copia señuelo de la aplicación, confirma el ataque de forma mecánica y propone, valida y despliega el parche.

## El problema

Entre que alguien explota una vulnerabilidad y el equipo despliega el arreglo pasan días. Los firewalls de aplicación deciden con reglas y puntajes: bloquean clientes legítimos y dejan pasar lo que no conocen.

## Cómo funciona

1. **Detecta.** Un gateway delante de la app envía los requests sospechosos a un clon: el mismo código, con datos sintéticos.
2. **Confirma.** En el clon hay "oráculos" que observan lo que la app hace de verdad: la consulta SQL, los archivos que abre, los procesos, la red y si devuelve datos de otro dueño. El veredicto lo da la ejecución, no un puntaje. Un falso positivo cuesta latencia, no un cliente bloqueado.
3. **Contiene.** El gateway activa una regla acotada al punto vulnerable. El atacante sigue en el clon.
4. **Cura.** Un modelo confinado propone un parche de código. No decide nada: el parche solo se despliega si pasa cinco validaciones mecánicas, y sale en blue/green con rollback.

## Qué se puede ver

- Una tienda de prueba con siete defectos plantados por el equipo: inyección SQL, path traversal y acceso a datos ajenos.
- El ciclo completo medido sobre esos siete defectos, tres rondas (2026-11-21, una máquina ARM64 de 4 núcleos compartida): 21 de 21 incidentes parchados por el modelo en el primer intento. Medianas desde que se abre el incidente: regla activa a los 1.9 s, parche en producción a los 24.9 s, verificado a los 51.3 s. Estas cifras son anteriores a las correcciones del 2026-11-22 y no se volvieron a medir; en ese momento la lista de defectos estaba dentro del árbol que el generador de parches podía leer.
- Las validaciones rechazando 15 parches inadecuados escritos a mano (listas negras, puertas traseras, funcionalidad borrada) y aceptando 7 correctos.
- `immune init` adaptando el sistema a otra aplicación FastAPI con SQLite, y un runtime genérico con oráculos fuera del proceso para una aplicación Node con Postgres.
- Modo de anticipación sobre software real: al revisar el código de Apache HTTP Server 2.4.49, el sistema propone un parche que da el mismo resultado que el cambio oficial de 2.4.50 en 21 de 21 vectores escritos por el equipo, sobre la función extraída y no sobre un servidor en marcha.

## Límites

Lo que los oráculos no ven, el sistema no lo aprende: fallas de lógica de negocio y ataques de segundo orden quedan fuera. La validación del diff es heurística y no hay un segundo modelo revisor. Los defectos del demo están plantados, no descubiertos, y no hubo equipo rojo. La falla de Apache es pública y conocida: demuestra el mecanismo, no un descubrimiento a ciegas. La lista completa está en `docs/limites.md` y las cifras en `docs/resultados.md`.

## Equipo

Nicolás Funes, Bautista Silvano, Isidro Pasman y Uriel Gandelman.
