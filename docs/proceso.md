# Cómo se construyó y cómo auditarlo

Tipo de documento: explicación, con una guía breve para reproducir la auditoría.

## Cómo se construyó

El código de Immune lo escribieron agentes de programación con IA (Claude), orquestados y revisados por el
equipo. El trabajo se hizo contra un contrato escrito ([`contracts/`](../contracts/README.md)) y contra tests de
aceptación (`acceptance/`) definidos antes de construir cada componente.

Quienes construyeron y quienes revisaron pertenecen a la misma familia de modelos. Sus puntos ciegos están
correlacionados: un error de razonamiento que comete el constructor es más probable que también se le escape al
revisor. Las consecuencias prácticas son tres:

- No hubo una revisión independiente por personas ajenas al equipo ni por un modelo de otra familia.
- No hubo equipo rojo ni una prueba con una vulnerabilidad plantada por alguien que no participó en la
  construcción.
- Los defectos de las aplicaciones de demostración los plantó el mismo equipo que construyó el sistema que los
  detecta.

Por eso la documentación separa lo medido de lo observado una vez ([resultados.md](resultados.md)) y lo construido
de lo diseñado ([arquitectura.md](arquitectura.md#7-diseñado-y-construido)), y reúne los límites en
[limites.md](limites.md).

El 2026-11-22 se hizo una auditoría del código y de la documentación. Entre sus correcciones: las listas de
defectos plantados salieron de los árboles de las aplicaciones hacia `docs/demo/respuestas/`, porque el generador
de parches copia el árbol de la aplicación para el modelo. Las cifras de tiempo de `resultados.md` son anteriores
a esa corrección.

Esa auditoría no cubrió el código que se incorporó después desde otra línea de trabajo: el canario de despliegue,
el sidecar unificado con MySQL y la traza de PHP, el vigilante de prod, el WAF de detección, la etapa de parche
para aplicaciones externas, los laboratorios de Grafana y ScadaBR, el ejemplo de OpenEMR y la demo de FUXA. Su
estado, y lo que se verificó de cada uno, está en la tabla de
[arquitectura.md](arquitectura.md#7-diseñado-y-construido) y en [resultados.md](resultados.md).

## Cómo reproducir la auditoría

Requisitos: el entorno de `install.sh` y Docker ([operacion.md](operacion.md#instalar)). Los comandos se ejecutan
desde la raíz del repositorio. Ninguno llama al modelo.

1. Tests, sin los que llaman al modelo:

   ```bash
   .venv/bin/pytest -q -m "not live"
   ```

2. Autotest de las validaciones: los parches correctos pasan y los inadecuados son rechazados por la validación
   esperada.

   ```bash
   .venv/bin/python -m pipeline.selftest
   ```

3. Análisis estático del Python versionado:

   ```bash
   .venv/bin/python -m pyflakes $(git ls-files '*.py')
   ```

4. Recalcular las cifras de tiempo a partir del archivo de datos:

   ```bash
   python3 -c "import json; d = json.load(open('docs/demo/metricas-tiempo-a-parche.json')); print(d['date'], d['host']); [print(k, v) for k, v in d['summary'].items()]"
   ```

5. Reevaluar el resultado guardado del modo de anticipación, sin llamar al modelo (necesita la imagen
   `immune-cbuild:1` y el directorio de un resultado bajo `runtime/anticipate/reports/`):

   ```bash
   immune anticipate recheck <directorio del resultado>
   ```

Los resultados esperados de los pasos 1 a 3 están en [resultados.md](resultados.md#2-tests-y-autotest).

Para contrastar la documentación con el código: los documentos de `docs/` citan el archivo, y donde aplica la
función, que respalda cada mecanismo. La fuente de toda cifra medida es `resultados.md`.
