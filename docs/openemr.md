# Inmune con OpenEMR 8.2.0

En Linux o WSL2, `IMMUNE_WITH_OPENEMR=1 ./install.sh` descarga las imágenes fijadas de
OpenEMR y MariaDB. `bin/immune doctor --prereqs --openemr` comprueba que estén disponibles.
Después de preparar el ejemplo con `fetch.py`, `bin/immune init --project examples/openemr/app`
detecta PHP y MySQL y valida la configuración generada. `bin/immune doctor --project examples/openemr/app`
comprueba la configuración y las imágenes requeridas por el proyecto.
Si el checkout ya tiene un `.venv` de Windows, usá `IMMUNE_VENV_DIR` con una ruta absoluta
de Linux tanto para instalar como para ejecutar `bin/immune` desde WSL2.
La demo funciona con Docker Engine dentro de Ubuntu. Cada base sombra tiene un límite de 1 GiB
para alojar en memoria la semilla y su copia durante el reinicio del clon.

OpenEMR **v8_2_0** (commit `6125a2fd8089c8bcc3848071c1293c60e27a7585`) protegido con el mismo flujo que la
Tienda: gateway (L0, reglas, sesiones), clones sombra con oráculos, incidente, regla de contención, parche con
5 gates, deploy blue/green y dashboard. **El código de OpenEMR no se modifica**: no hay vulnerabilidades
sembradas. Cuando no existe un parche seguro, el incidente cierra como `rule_only` con la regla activa y con la
**línea exacta de PHP** donde ocurre el problema.

## Versión exacta

- `fetch.py` clona el tag `v8_2_0`, rechaza cualquier otro commit y verifica que `version.php` diga 8.2.0.
  El onboarding (`.immune/`, `immune-runtime/`, `Dockerfile.immune`) se agrega encima, y el script comprueba
  que `git diff v8_2_0` del código de OpenEMR esté vacío.
- La imagen base es la oficial, fijada por digest:
  `openemr/openemr:8.2.0-2026-11-21@sha256:98004b0a…`. Se verificó que sus 5254 archivos PHP (`interface/`,
  `library/`, `src/`, `apis/`, `portal/`, `controllers/`, `oauth2/`, `templates/`, `gacl/`, `ccr/`, `sql/`)
  son byte a byte los del tag.
- Base de datos: `mariadb:11.8.8@sha256:be1ef4fe…`, la del `docker-compose` oficial del tag.

## Uso (Linux o WSL2 con Docker, igual que tareas-node)

    python examples/openemr/fetch.py                 # examples/openemr/app, tag openemr-t0
    bin/immune up --project examples/openemr/app     # gateway :8280, dashboard :8290
    python examples/openemr/legit.py --base http://127.0.0.1:8280 --duration 120
    python examples/openemr/attacks.py --base http://127.0.0.1:8280
    bin/immune status --project examples/openemr/app
    bin/immune down --project examples/openemr/app

La primera vez `immune up` instala OpenEMR con **su propio instalador** (`auto_configure.php`) contra la base
demo y carga **Clínica Delta**, con datos 100 % sintéticos (`immune-runtime/seed-clinic.php`).
Cuentas: `admin / Inmune-admin-82`, `medico1 / Inmune-medico1-82`, `medico2 / Inmune-medico2-82`,
`medico3 / Inmune-medico3-82` (con TOTP: el login web pide el código de 6 dígitos), `recepcion / Inmune-recepcion-82`
y las cuentas portal `paciente1 / Inmune-paciente1-82`, `paciente2 / Inmune-paciente2-82`. El secreto TOTP de
`medico3` es fijo para que la demo sea reproducible: `INMUNEMFADEMO2TOTPSECRETA2B3C4D5` (el seed lo imprime
al correr). Para proteger una base real, exportá
`OPENEMR_DATABASE_URL=mysql://usuario:clave@host:3306/openemr`.

## Qué agrega Inmune

- **Base de datos MySQL/MariaDB** en el runtime genérico (`immune/dbkind.py`):
  - proxy del protocolo en el sidecar (`sidecar/mysqlproxy.py`): observa las sentencias ejecutadas, desactiva
    TLS y compresión en el handshake y anota las tablas escritas;
  - cliente admin (`sidecar/mysqlclient.py`);
  - reset L1 que reconstruye sólo las tablas escritas desde la base `seed` (en la práctica, milisegundos);
  - dialecto MySQL en el oráculo SQL (`shadow/sqltaint.py`, escapes `\'`, comentarios `#` y `-- `), así un
    `O\'Brien` escapado por la app no es un falso positivo;
  - datos sombra desde la base de prod (`immune/shadowdata_mysql.py`): misma semántica de `columns.yaml`,
    lectura en sesiones de sólo lectura y auto-chequeo de fugas.
- **Dónde en el código** (`sidecar/phptrace.py`): los clones (nunca prod) corren `<imagen>-trace`, que es la
  imagen del release más Xdebug en modo traza.
  - Sólo se traza el request que se juzga: el sidecar le pone la cookie `XDEBUG_TRACE`.
  - `vendor/` queda excluido, así que una página traza unos 2 MB en vez de 50 MB.
  - Cada evento de oráculo recibe su pila PHP (`stack`, el sumidero al final). El incidente, el dashboard y el
    prompt del patcher la usan.
- **Identidad en los clones** (`.immune/openemr_identity.py`):
  - contraseña aleatoria por proceso (SHA-512 crypt, que OpenEMR verifica nativamente);
  - login real, igual que un navegador;
  - cookie de sesión y `APICSRFTOKEN` del clon, y reescritura de `csrf_token_form`.
  - En prod el gateway identifica la sesión con `/_immune/whoami` (`auth.kind introspect`).
- **Contenedor endurecido**: Apache + mod_php como `apache` en `:8080`, sistema de archivos de sólo lectura, sin
  capacidades. El único árbol escribible de OpenEMR (`sites/default/documents`) vive en `/tmp`. Hay un pool
  fijo de workers, así que no se crean procesos durante un request (el oráculo `proc` no da falsos positivos).
- **Pipeline**:
  - léxico PHP en el gate de política de diffs: `require/include/use`, `shell_exec`, `unserialize`… Un parche
    que quite `aclCheckCore` o `verifyCsrfToken` queda rechazado.
  - el patcher usa la pila para elegir los archivos y recibe guía de binds `?` de `sqlStatement`/ADOdb;
  - `legit.normalize` ignora tokens CSRF y marcas de tiempo al comparar respuestas;
  - `auth.login` permite verificar después del deploy sin auto-registro.
  - El juez monta el release parcheado **por ruta**, para no tapar `vendor/` de la imagen.

## Lo verificado en vivo (Docker)

Un clon completo: MariaDB del clon, OpenEMR `-trace` y sidecar con strace y proxy MySQL.

| Request | Veredicto |
|---|---|
| login, buscador de pacientes, API REST, FHIR Patient, consulta ligada con `O'Brien` | `clean` |
| SQLi de prueba (fixture sólo del harness) | `oracle sql`, pila `library/sql.inc.php:99` ← script |
| traversal de prueba a `/etc/hostname` | `oracle file`, pila `…/immune_fixture.php:13 readfile` |
| sonda SQLi contra la búsqueda real de OpenEMR | `clean` (8.2.0 parametriza esa consulta) |

## Límites, dichos

- OpenEMR controla el acceso por ACL, no por "dueño". Por eso los pacientes no tienen `owner` en
  `columns.yaml`: una regla de dueño marcaría como ataque el acceso legítimo de cualquier clínico. El oráculo
  `owner` sólo cubre datos de cada cuenta (notas, hashes, MFA). La PHI de los pacientes nunca llega a la
  sombra: sus campos se reemplazan por valores sintéticos y la auditoría por valores aleatorios.
- Archivos que PHP ya abre durante el warm-up (por ejemplo `/etc/passwd`) quedan permitidos, con la misma
  regla del sidecar para cualquier app. Un traversal a otros archivos sí dispara.
- Los documentos subidos viven en `/tmp` del contenedor: un cambio de color blue/green no los conserva. Los
  de la demo están en la imagen.
- La imagen oficial no trae PHPUnit. El gate `tests` hace `php -l` de los archivos parcheados y verifica que
  OpenEMR siga arrancando.
- Si no hay Claude CLI no hay parche automático (el runtime genérico no tiene parches de reserva): el resultado
  es la regla más la ubicación.

## Las cinco CVE de 8.2.0 y qué las deja expuestas

OpenEMR 8.2.0 trae las cinco fallas de serie; ninguna está sembrada. El seed (`immune-runtime/seed-clinic.php`)
solo enciende las superficies que el release trae apagadas o que un administrador real no habría configurado,
y crea las cuentas que permiten mostrar el impacto. Todas quedan cubiertas por el flujo Inmune: request
sospechoso → clon sombra → oráculo → incidente con la línea exacta de PHP (o regla de contención).

| CVE | Fallo | Dónde está el código | Qué lo expone en el demo |
|---|---|---|---|
| CVE-2026-39932 (RCE) | `eval()` de un string armado desde `categories` donde la columna `id` se concatena cruda (CWE-95); el tipo INT de la columna es la única barrera | `library/classes/Tree.class.php:119`, `:124` y `:141` | `configuration_import_export=1` (seed) le da a `admin` la primitiva de SQL arbitrario (backup.php → Import Configuration): `ALTER TABLE categories MODIFY COLUMN id VARCHAR(255)` + INSERT de una fila con el payload en `id` (lft/rght dentro de los bounds del root) — cualquier página que arme el árbol (`GET /controller.php?document_category&list`) ejecuta el payload |
| CVE-2026-67610 (OAuth2/FHIR) | Registro dinámico de clientes sin autenticación (CWE-306) | endpoint `/oauth2/default/registration` (`src/RestControllers/AuthorizationController.php`) | `rest_api=1` + `rest_fhir_api=1` + `rest_system_scopes_api=1` (seed, los mismos conectores que enciende el CI de OpenEMR). El cliente malicioso queda pendiente de aprobación admin; aprobado, `client_credentials` con JWT firmado por su propia `jwks` da acceso de lectura a todos los recursos FHIR |
| CVE-2026-67611 (MFA bypass) | El password grant solo valida el TOTP si el request trae `mfa_token` | `src/Common/Auth/OpenIDConnect/Repositories/UserRepository.php:111` (sin `mfa_token` retorna `true` en la línea 135) | `oauth_password_grant=3` (seed, igual que el CI de OpenEMR) + TOTP registrado para `medico3` (seed): el login web de `medico3` exige el segundo factor, el token OAuth2 no |
| CVE-2026-124471 (facturación) | Sin chequeo de ACL en la factura de un encuentro (CWE-639) | `interface/billing/sl_eob_invoice.php` (corregido en 8.3.0) | Nada que activar: cualquier usuario autenticado (p. ej. `recepcion`, Front Office) lee y modifica la cuenta de cualquier `id` |
| CVE-2026-67612 (XSS portal) | Las plantillas del portal guardan todo salvo el literal `<?php` y se devuelven sin codificar; cookies de sesión core sin HttpOnly por diseño | `portal/import_template.php:125` (save), `mode=get` (línea 64), `src/Common/Session/SessionUtil.php:9` | `portal_onsite_two_enable=1` + `portal_onsite_two_basepath=1` (seed) y pacientes portal (`paciente1`, `paciente2`): una plantilla envenenada por el admin roba `document.cookie` de quien la vea |

Notas:

- `rest_portal_api=1` (seed) habilita la API del portal, para que los tokens de paciente tengan superficie
  REST que ejercitar.
- `rest_system_scopes_api=1` (seed) acepta scopes `system/` de FHIR, los que usa el cliente del CVE-2026-67610.
- `configuration_import_export=1` (seed) habilita el «Import Configuration» de backup.php: la primitiva de
  SQL arbitrario que la cadena del CVE-2026-39932 necesita (sin ella, el admin solo cambia `name`/`value` de
  categorías y el `eval()` no ejecuta nada).
- Si `app/` se regenera con `python examples/openemr/fetch.py`, el seed del overlay se copia encima: los
  cambios viven en `examples/openemr/overlay/immune-runtime/seed-clinic.php`.
- Para apagar una falla en la demo, alcanza con editar el `foreach` de globals del seed (por ejemplo,
  `oauth_password_grant` en `0` cierra el bypass) y reinstalar la base demo.
