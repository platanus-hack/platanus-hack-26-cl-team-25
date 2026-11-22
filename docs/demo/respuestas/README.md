# Listas de defectos plantados

`tienda.md`, `notas.md` y `tareas-node.md` enumeran los defectos que el equipo plantó en las tres aplicaciones de
demostración (`victim/`, `examples/notas/`, `examples/tareas-node/`): 7, 4 y 3. Cada entrada indica la ruta, el
archivo y cómo se explota el defecto.

Están fuera de los árboles de las aplicaciones a propósito. El generador de parches y `immune init` copian el
árbol de la aplicación para que el modelo lo lea; una lista de respuestas dentro de ese árbol invalidaría los
resultados. `pipeline/selftest.py` lee `tienda.md` desde aquí.
