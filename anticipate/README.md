# anticipate — modo anticipación sobre software real

Revisión defensiva de **código fuente público** de una versión publicada que después se corrigió upstream.
No ejecuta el servidor ni envía tráfico: todo es lectura de código, un parche propuesto y pruebas unitarias en un contenedor sin red.

```
.venv/bin/python -m anticipate list
.venv/bin/python -m anticipate check apache-httpd-2.4.49     # solo chequeo mecánico, sin modelo (~10 s)
.venv/bin/python -m anticipate run   apache-httpd-2.4.49     # modelo + chequeos + comparación + reporte (~45 s)
.venv/bin/python -m anticipate recheck <dir del reporte>     # re-evalúa un resultado guardado, sin llamar al modelo
```

Reportes en `runtime/anticipate/reports/<target>/<fecha>/report.html` (autocontenido) y `report.md`.

## Qué hace `run`

1. Descarga el código de las dos etiquetas públicas (`vulnerable_ref`, `fixed_ref`) en un repo en caché.
2. **Chequeo base:** extrae las funciones indicadas de la versión publicada y las compila con un shim y una batería de vectores; muestra qué propiedades fallan.
3. **Revisión por el modelo**, con el mismo confinamiento que el agente de parches (`patcher/claude_cli.py`: solo Read/Edit, solo dentro de una copia de los archivos en alcance). Se le da el área y la clase de defecto; **no** el aviso ni la versión corregida (`tests/test_anticipate.py` lo verifica).
4. **Chequeo del parche sugerido y del oficial** con la misma batería, y comparación: vectores con resultado idéntico, misma función, líneas superpuestas, tamaño.
5. Reporte con hallazgos, los dos diffs lado a lado y la tabla de vectores.

## Targets

`targets/<id>/target.yaml`: repo, refs, clase, área (texto que ve el modelo), alcance, contexto de solo lectura, y el chequeo (`check`: archivo, funciones a extraer, shim, vectores). El chequeo actual (`c-function` + normalizador de rutas) es específico de este target; otro target necesita su propio harness.

## Resultado medido (2026-11-21, dos corridas con `opus`)

| | Propiedades |
|---|---|
| 2.4.49 publicada | 14/21 |
| Parche sugerido | 21/21 |
| 2.4.50 oficial | 21/21 |

Sugerido vs oficial: 21/21 vectores con resultado idéntico, misma función (`ap_normalize_path`). Unos 35 s por revisión.

## Límites (decirlos en el demo)

- **Contaminación:** el defecto es público y famoso; el modelo casi seguro lo vio en entrenamiento. En la primera corrida el comentario del parche fue casi textual al oficial. Esto demuestra el mecanismo (detectar, parchear, validar, comparar), no capacidad de descubrimiento ciego. Para una prueba ciega hace falta un aviso posterior a la fecha de corte del modelo.
- **El alcance lo elige el operador** (un archivo aquí). Con todo el repo la revisión sería mucho más cara e incierta.
- **El chequeo es unitario** sobre la función aislada, no un build ni la suite de Apache.
- Para software de terceros, en producción lo correcto es contener con la regla del gateway y actualizar a la versión corregida; el parche sugerido es evidencia de que el sistema entendió la causa.
