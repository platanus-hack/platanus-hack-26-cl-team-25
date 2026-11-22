# Guion de la demo y preguntas difíciles

Tipo de documento: guía de tareas. Para quien presenta. Las cifras vienen de [../resultados.md](../resultados.md);
los límites, de [../limites.md](../limites.md).

## Antes de subir al escenario

1. Desde la raíz del checkout: `immune reset` y después `immune status`, que tiene que terminar en `healthy`.
2. Abrir el panel en `http://127.0.0.1:8090`, en pantalla completa. En un proyector de 1024×768 el panel pasa a
   dos columnas y se sigue leyendo; con 1920×1080, usar zoom del navegador al 125 %.
3. Dejar abierta una terminal con letra grande en la raíz del checkout y este comando escrito, sin ejecutar:

   ```bash
   .venv/bin/python -m sim.attacker --interval 1.5 --until-closed 2
   ```

4. En otra terminal, tráfico legítimo de fondo para que el panel no esté quieto:

   ```bash
   .venv/bin/python -m sim.legit --base http://127.0.0.1:8080 --rate 3
   ```

5. Tener a mano el video de respaldo (`deploy/record_demo.sh` lo graba; ver abajo) abierto en el reproductor, en
   pausa en el primer cuadro.

## La demo, en tres minutos

| Tiempo | Pantalla | Qué decir |
|---|---|---|
| 0:00 | Terminal | "Este es un atacante automático. Repite siete ataques conocidos contra una tienda con siete defectos que plantamos nosotros." Enter. |
| 0:10 | Terminal, líneas amarillas | "Amarillo quiere decir que el ataque funcionó, pero sobre un clon con datos sintéticos. El atacante cree que ganó y no tocó producción." |
| 0:20 | Panel, incidente abierto | "El clon lo confirmó por ejecución: vimos la consulta SQL. En unos dos segundos hay una regla en el gateway que cierra solo ese punto." |
| 0:40 | Panel, detalle del incidente | "Un modelo confinado propone un diff. No decide nada: pasa cinco validaciones mecánicas, se despliega en blue/green y se verifica." |
| 1:30 | Terminal, líneas verdes | "Verde: bloqueado. El código de producción ya está corregido; no depende de la regla." |
| 2:30 | Panel, Bot atacante | "Rojo sería datos reales filtrados. No aparece nunca." |

Si algo titubea en vivo: cortar y poner el video. No intentar arreglarlo frente al jurado.

## Video de respaldo

```bash
PLAYWRIGHT_CORE_DIR=<directorio con node_modules/playwright-core> deploy/record_demo.sh
```

Hace `immune reset`, lanza tráfico legítimo y el atacante, y graba el panel con la terminal del atacante al lado
hasta que los siete exploits quedan bloqueados dos rondas seguidas. Deja `demo.webm`, `attacker.log` y capturas a
1920×1080, 1280×720 y 1024×768 en `runtime/recording-<fecha>/`.

## Cómo marcar el límite antes de que lo marque el jurado

Decirlo en el pitch, con estas palabras o parecidas:

> "Probamos el mecanismo con tres clases de vulnerabilidad sobre aplicaciones que escribimos nosotros, y el modo
> de revisión sobre un CVE público de Apache. No es un descubrimiento a ciegas: el siguiente paso es una prueba
> con defectos que plante alguien ajeno al equipo y poner el gateway delante del portal web real de una
> sanitaria. No defendemos el PLC: defendemos el portal web, que es por donde entraron en el caso Kemuri."

## Preguntas difíciles

**"Sus validaciones usan su propio tráfico legítimo y sus propios parches de prueba. ¿No es circular?"**
En parte sí, y está escrito en [../validaciones.md](../validaciones.md). El autotest demuestra que cada
validación rechaza lo que dice rechazar (15 parches malos escritos a propósito, cada uno atrapado por la
validación esperada), no que sea un juez general. En una aplicación real, `legit` vuelve a ejecutar el tráfico
grabado de esa aplicación, no el nuestro, y si no hay tráfico que cubra la ruta, el parche queda como pull request
para un humano: no se mergea solo. Eso pasó con dos de los tres defectos de `examples/tareas-node`.

**"21 de 21 sobre una app de juguete con bugs que ustedes plantaron."**
Correcto, y lo decimos: es una medición del mecanismo y del tiempo, no de generalización. La cifra es del
2026-11-21, anterior a la auditoría del 22, y no se volvió a medir ([../resultados.md](../resultados.md)). Lo
que falta es una prueba ciega con defectos plantados por alguien de afuera.

**"El modelo seguramente conocía el CVE de Apache."**
Sí. Por eso el reporte dice que demuestra el mecanismo (revisar, parchar, validar, comparar con el arreglo
oficial) y no un descubrimiento. Para afirmar descubrimiento haría falta un aviso posterior a la fecha de corte
del modelo.

**"¿El traversal y el IDOR quedaron cerrados de punta a punta fuera de la tienda?"**
En `examples/tareas-node`, no: se detectaron, tuvieron regla y pull request, pero no se mergearon porque no había
tráfico legítimo grabado de esas rutas. Es el comportamiento elegido: sin evidencia de que el parche no rompe a
los clientes, decide un humano.

**"¿Esto corre delante del servicio real de un cliente?"**
Hoy no. `immune deploy` es un esbozo y lo dice al ejecutarse. El camino que funciona es `immune up`, que levanta
una copia de la aplicación detrás del gateway.

**"El patcher usa las credenciales de Claude de la máquina."**
Por defecto sí. Se le puede dar una identidad propia (`PATCHER_CLAUDE_CONFIG_DIR` o `PATCHER_ANTHROPIC_API_KEY`) y
el proceso del modelo no hereda el entorno del pipeline: no ve los tokens del stack. Solo tiene las herramientas
de leer y editar archivos de una copia del código; no hay shell. No hay un sandbox del sistema operativo
alrededor de ese proceso.

**"¿Deployar código escrito por un LLM en una planta de agua, sin humano?"**
No lo proponemos. `immune init` deja `autopatch: pr`: el parche validado queda como pull request y lo mergea una
persona; el merge automático hay que activarlo a mano. El demo usa `merge` para mostrar el ciclo completo. La
regla de contención, que sí es automática, no cambia código: solo fuerza que ese punto se ejecute en el clon. Si
un parche ya desplegado hay que sacarlo, `immune rollback` vuelve a la release anterior por el mismo camino
blue/green, reactiva la regla de contención de cada defecto que ese parche cerraba y deja el autopatch en `pr`; además hay rollback automático si sube la tasa de 5xx en los 20 segundos
posteriores al cambio.

**"¿Cuánto les cuesta esto a los clientes legítimos?"**
En la corrida del 2026-11-22, 82 de 4551 requests de clientes recibieron un 404 ([../resultados.md](../resultados.md)).
Casi todos por lo mismo: mientras la regla de un IDOR espera su parche, cubre todos los valores de la ruta, y el
clon no tiene los objetos creados después de la semilla. Un cliente que pide su propio pedido nuevo recibe 404
hasta que el parche se verifica, unos 70 segundos en el demo. Con `autopatch: pr`, dura hasta que una persona
mergea. Está en [../limites.md](../limites.md); es lo primero que habría que resolver antes de un piloto.
