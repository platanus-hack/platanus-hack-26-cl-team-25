#!/bin/sh
# Regla de POLITICA opcional para la demo OpenEMR (POST /_admin/rules del admin del gateway en :8281).
#
# Las reglas viven en el estado del run (GW_STATE_PATH): correrlas despues de cada `immune up`.
#
# ARRANCA EN CERO: las detecciones del IDOR (2026-124471), del MFA bypass (2026-67611) y del XSS
# (2026-67612) son emergentes y no necesitan ninguna regla —
#   * sl_eob_invoice.php esta marcada x-owner-scoped (con id como x-owner-id): toda lectura de un no
#     admin y la iteracion de ids se detonan solas, y el oraculo `acl` replayea el acct/bill que el
#     app se salto;
#   * /oauth2/default/token esta marcada x-owner-scoped: los grants sin sesion se detonan solos y el
#     oraculo `mfa` confirma el bypass con su sonda por ejecucion;
#   * el save del portal ya se detona por la gramatica (grammar:form.content) y el oraculo `xss`
#     corta el payload en el clon.
# La salida del sistema (la regla de contencion que nace de cada incidente) sigue siendo automatica:
# el pipeline la activa cuando el oraculo confirma.
#
# La unica regla que esta script siembra es fhir-patient-anon (CVE-2026-67610): politica de la clinica,
# no conocimiento aprendido — "Patient sin sesion web no se sirve" (los system tokens no crean sesion).
# El clon no puede validar un Bearer de prod (401 -> inconcluso), asi que la cobertura FHIR es de
# contencion: la regla es ESTRICTA y niega lo inconcluso. Sin ella, la lectura masiva anonima pasa.
#
# Uso:  bash examples/openemr/seed-rules.sh
set -eu
cd "$(dirname "$0")/../.."
RT=examples/openemr/app/.immune/runtime/stack/containers.env
[ -f "$RT" ] || { echo "no hay stack arriba (falta $RT): corre bin/immune up primero" >&2; exit 1; }
TOK=$(grep -oE '^ADMIN_TOKEN=.*' "$RT" | cut -d= -f2)

echo "--- regla de politica: fhir-patient-anon"
curl -s -X POST http://127.0.0.1:8281/_admin/rules \
  -H "x-admin-token: $TOK" -H 'Content-Type: application/json' \
  -d '{"id":"fhir-patient-anon","method":"GET","route":"/apis/default/fhir/Patient","scope":"all","identity":"untrusted"}'
echo
echo "--- reglas activas ahora:"
curl -s http://127.0.0.1:8281/_admin/rules -H "x-admin-token: $TOK"
echo
