# Immune

**Un sistema inmunológico para tu app.** Atrapa al atacante en una copia señuelo, confirma el ataque de forma mecánica y parchea la falla sola.

## El problema

Entre que alguien explota una vulnerabilidad y el equipo despliega el arreglo pasan días. Los firewalls de aplicación adivinan con reglas y puntajes: bloquean clientes legítimos y dejan pasar lo que no conocen.

## Cómo funciona

1. **Detecta.** Un gateway delante de la app manda los requests sospechosos a una copia sombra: el mismo código, con datos sintéticos.
2. **Confirma.** En la sombra hay "oráculos" que miran lo que hace la app de verdad: la consulta SQL, los archivos que abre, los procesos, la red y si devuelve datos de otro dueño. El veredicto lo da la ejecución, no un puntaje. Un falso positivo cuesta unos milisegundos, nunca un cliente bloqueado.
3. **Contiene.** En segundos, el gateway activa una regla acotada al punto vulnerable. El atacante sigue en el señuelo sin enterarse.
4. **Cura.** Un LLM confinado propone un parche de código. No decide nada: el parche solo se despliega si pasa cinco validaciones mecánicas, y sale en blue/green con rollback.

## Qué se puede ver

- Una tienda de prueba con siete vulnerabilidades reales (inyección SQL, path traversal y acceso a datos ajenos).
- El ciclo completo en vivo para inyección SQL: regla a los 15 segundos, parche validado y desplegado en 60.
- Las validaciones rechazando 15 parches malos (listas negras, puertas traseras, funcionalidad borrada) y aceptando 7 correctos.
- Modo anticipación sobre software real: revisando el código de Apache HTTP Server 2.4.49, el sistema propone un parche que se comporta igual que el oficial en 21 de 21 casos.

## Límites

Lo que los oráculos no ven, el sistema no lo aprende: ataques de segundo orden y fallas de lógica de negocio quedan afuera. La falla de Apache es pública y conocida, así que demuestra el mecanismo, no un descubrimiento a ciegas.

## Equipo

Nicolás Funes, Bautista Silvano, Isidro Pasman y Uriel Gandelman.
