# Demo defensiva de Immune con FUXA v1.2.9

La demo usa únicamente el commit oficial 19c2471833e410eea235b81857ddcfde7b3851a0. Docker ejecuta el servicio FUXA en una red interna. El gateway publica la interfaz en 127.0.0.1:1881 y conserva la revisión anterior hasta verificar el cambio.

Instala las dependencias de Python y activa los contenedores Linux de Docker. Ejecuta estos comandos desde la raíz de Immune.

    python -m immune fuxa baseline
    python -m immune fuxa up
    python -m immune fuxa status
    python -m immune fuxa watch

Ejecuta «python -m immune fuxa dashboard» en otra terminal para ver la revisión activa, las alertas del monitor y el historial de parches. El dashboard escucha en http://127.0.0.1:8091. Usa el mismo directorio --runtime para el monitor y el dashboard.

La opción --repo de baseline reutiliza un repositorio local con la etiqueta v1.2.9. La primera construcción requiere acceso al registro de npm y a los repositorios del sistema base. La opción --port de up permite elegir otro puerto local.

FUXA carga Estación Delta, un proyecto HMI de tratamiento de agua con un tanque, una bomba y una alarma de nivel alto. Las mediciones se actualizan cada dos segundos con datos generados localmente. La alarma se activa a partir del 85 % y vuelve a condición normal al bajar el nivel.

En otra terminal, ejecutar «python -m immune fuxa demo» para entregar evidencia sintética de una operación que siga en observación. Fleet genera el diff, aplica el control a una copia de la revisión, ejecuta las comprobaciones del control y la suite de FUXA, compara /api/version y / y cambia el upstream. La evidencia sintética queda marcada como tal. El comando status muestra la revisión que sirve el gateway. El comando down detiene la demo.

Para revisar registros exportados, ejecutar «python -m immune fuxa watch --input RUTA». El analizador reconoce los formatos combined y dev de Morgan. Devuelve alertas por respuestas 401 y 403 en las operaciones cubiertas, con la ruta y el número de línea. El despliegue requiere evidencia estructurada del servidor.

El archivo runtime/fuxa/profile.json guarda la política y el inventario. El directorio runtime/fuxa/incidents/ contiene los resultados y diffs por incidente. La detección observa dos efectos administrativos cuando están por ocurrir, la escritura de configuración y el despacho de funciones del sistema. El parche activa el control de autorización en el efecto observado. Otras rutas y eventos Socket.IO aparecen como pendientes. Cada contenedor arranca con datos de demo efímeros y un secreto de sesión nuevo, por lo que un cambio de revisión reinicia sesiones y estado local.
