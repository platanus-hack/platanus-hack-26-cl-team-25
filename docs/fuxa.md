# Demo defensiva de Inmune con FUXA v1.2.9

La demo usa únicamente el commit oficial 19c2471833e410eea235b81857ddcfde7b3851a0. Docker ejecuta el servicio FUXA en una red interna. El gateway publica la interfaz en 127.0.0.1:1881 y conserva la revisión anterior hasta verificar el cambio.

Instala las dependencias de Python y activa los contenedores Linux de Docker. Ejecuta estos comandos desde la raíz de Inmune.

    python -m immune fuxa baseline
    python -m immune fuxa up
    python -m immune fuxa status
    python -m immune fuxa watch

Ejecuta «python -m immune fuxa dashboard» en otra terminal para ver la revisión activa, las peticiones del gateway, las alertas del monitor y el historial de parches. Cada petición muestra método, ruta, estado y latencia. Las respuestas HTTP 401 y 403 aparecen como sospechosas. Las detecciones confirmadas requieren evidencia del monitor. El dashboard escucha en http://127.0.0.1:8091. Usa el mismo directorio --runtime para el monitor y el dashboard.

Cada petición que atraviesa el gateway lleva un identificador de operación («Peticiones en vivo» y «Detecciones de Inmune» comparten ese id). El gateway lo añade como cabecera al reenviar la petición; el servidor lo reutiliza en la evidencia del efecto y en la decisión de política. En Socket.IO la unidad es el evento: el HTTP 200 confirma la entrega del mensaje y el veredicto indica si se permitió el efecto, y ambos se unen por el identificador de sesión y el nombre de la operación. Así una escritura de tag aparece como una sola operación con su veredicto: permitida, bloqueada, sin cobertura o evaluación no disponible. El HTTP 200 queda etiquetado como entrega confirmada.

El gateway rechaza con 403 los cambios del programador sin token. Los controles del servidor exigen un administrador autenticado para cambiar programaciones, escribir tags, controlar dispositivos y consultar el histórico. El resultado de una consulta del histórico se entrega a la sesión autorizada que la hizo. Los clientes invitados pueden usar las lecturas ordinarias del HMI.

Antes de ejecutar una operación protegida, FUXA verifica la identidad y envía únicamente la operación y el rol efectivo a un hilo dedicado de evaluación. El hilo decide si la política permite el efecto. FUXA vuelve a verificar el permiso al aceptar la decisión. Si el evaluador no responde, la operación se detiene y el dashboard registra «Evaluación no disponible». Los registros identifican la operación y el resultado, sin guardar credenciales ni contenidos.

El gateway marca los mensajes sensibles de Socket.IO por HTTP long-polling y muestra el motivo sin guardar los datos del mensaje. Las conexiones WebSocket y los mensajes de polling que superan el límite de 64 KiB aparecen como «Sin inspección» en el registro del gateway. El control del servidor se aplica a los eventos sensibles de ambos transportes y reporta los bloqueos al monitor.

Cuando una sesión acumula denegaciones repetidas de la misma operación, Inmune registra una restricción temporal sobre esa sesión y las operaciones afectadas. La restricción vive dentro del servidor, con la sesión ya autenticada, vence por sí sola y no afecta a la actividad ordinaria como leer el HMI. El panel «Restricciones de sesión» del dashboard muestra qué se restringió, el motivo y cuándo vence. Las claves de sesión son opacas: identificador de Socket.IO o resumen del token, sin guardar credenciales.

En una instancia activa, el comando harden activa las políticas administrativas conocidas y valida la revisión candidata en un contenedor sin red con sesiones, credenciales y estado sintéticos. Comprueba el efecto permitido o denegado sobre tags, dispositivos, histórico y programaciones. Luego ejecuta la suite de FUXA y verifica el servicio por el gateway antes de conservar el cambio. La revisión anterior queda disponible. El resultado de la validación aparece en status y en el dashboard. El comando reload-gateway actualiza el gateway y comprueba que la revisión activa siga respondiendo.

El comando validate-active ejecuta la validación en contenedores de prueba con la misma imagen y los mismos archivos instrumentados de la revisión en servicio. La instancia activa continúa atendiendo peticiones.

El comando audit-coverage comprueba que los controles declarados sigan conectados al código de la revisión activa y genera coverage-audit.json junto al informe de validación. El informe identifica la ubicación de cada ruta de lectura, ruta de escritura o evento que requiera revisión. La auditoría también se ejecuta al validar una candidata. Las entradas pendientes indican falta de cobertura verificada de Inmune.

Las verificaciones del gateway comprueban el proyecto HMI, el rechazo de lectura de usuarios como invitado y la apertura del canal de datos en vivo. Se ejecutan al subir la demo, actualizar el gateway, validar la revisión activa y después de cambiar de revisión. Si un candidato falla después del cambio, Fleet restaura la revisión anterior y comprueba que vuelva a funcionar. El historial distingue un candidato rechazado de una reversión verificada.

El modo de parches predeterminado es auto. Con «python -m immune fuxa patch-mode review», las validaciones dejan el candidato pendiente de aprobación y el dashboard lo muestra en Incidentes. «python -m immune fuxa approve ID» comprueba que el candidato y la revisión de origen sigan vigentes antes de validar de nuevo y desplegar.

La opción --repo de baseline reutiliza un repositorio local con la etiqueta v1.2.9. La primera construcción requiere acceso al registro de npm y a los repositorios del sistema base. La opción --port de up permite elegir otro puerto local.

Si la instancia activa está en otro directorio dentro de runtime, status, watch, dashboard y demo la encuentran cuando hay una sola instancia activa. Status muestra el directorio seleccionado. Para elegirlo explícitamente, ejecuta «python -m immune fuxa --runtime RUTA status». Usa la misma opción con baseline, up y down al administrar esa instancia.

FUXA carga Estación Delta, un proyecto HMI de tratamiento de agua con un tanque, una bomba y una alarma de nivel alto. Las mediciones se actualizan cada dos segundos con datos generados localmente. La alarma se activa a partir del 85 % y vuelve a condición normal al bajar el nivel.

En una revisión heredada que mantenga una operación en observación, «python -m immune fuxa demo» entrega evidencia sintética de esa operación. Fleet genera el diff, aplica el control a una copia de la revisión, ejecuta las validaciones y comprueba el gateway tras el cambio. La evidencia sintética queda marcada como tal. Las instalaciones nuevas activan ambos controles administrativos desde el inicio. El comando status muestra la revisión que sirve el gateway. El comando down detiene la demo.

Para revisar registros exportados, ejecutar «python -m immune fuxa watch --input RUTA». El analizador reconoce los formatos combined y dev de Morgan. Devuelve alertas por respuestas 401 y 403 en las operaciones cubiertas, con la ruta y el número de línea. El despliegue requiere evidencia estructurada del servidor.

El archivo runtime/fuxa/profile.json guarda la política y el inventario. El directorio runtime/fuxa/incidents/ contiene los resultados y diffs por incidente. La detección observa dos efectos administrativos cuando están por ocurrir, la escritura de configuración y el despacho de funciones del sistema. El parche activa el control de autorización en el efecto observado. Otras rutas y eventos Socket.IO aparecen como pendientes.

El inventario declara para cada entrada quién puede ejecutarla y qué efecto debe observarse: las escrituras HTTP piden un administrador, las lecturas un usuario autenticado y los eventos de Socket.IO un administrador. Las pruebas sintéticas comprueban, por operación, que el rol autorizado consiga el efecto y que el rol sin permiso no lo consiga; si este último lo consigue, la evidencia abre un incidente.

Además de los controles confirmados, cada revisión declara guardas de ruta para las escrituras HTTP sin cobertura verificable. Cada guarda se inserta antes del efecto y arranca en observación; sólo un incidente la pasa a enforce. Si una ruta no permite verificar el punto de inserción, la guarda no se declara y la entrada sigue pendiente. El historial del incidente registra las puertas del candidato: la política de cambios, la prueba del efecto indebido, la validación aislada, la conservación del proyecto y las sesiones tras el cambio de revisión, y los flujos legítimos por el gateway. El dashboard distingue un bloqueo por un control existente, un incidente confirmado y un parche verificado.

El proyecto, las cuentas, las programaciones y la configuración de sesión se guardan en un volumen de Docker. Al cambiar de revisión, Fleet aísla la anterior y copia el estado a otro volumen antes de arrancar la candidata. El gateway cambia de destino después de verificar el proyecto y la configuración de sesión. Las conexiones en vivo se reconectan durante el cambio. El comando down conserva el volumen para el próximo up. Los registros de proceso y el estado de simulación en memoria se recrean al arrancar.
