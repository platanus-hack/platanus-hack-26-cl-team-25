"""Write examples/openemr/overlay/.immune/shadow/columns.yaml from the schema of an installed OpenEMR 8.2.0.

usage: gen_columns.py columns.tsv out.yaml   (columns.tsv: table, column, data_type, column_key from information_schema)
"""
import re
import sys

rows = [l.rstrip("\n").split("\t") for l in open(sys.argv[1], encoding="utf-8") if l.strip()]
cols = {}
for t, c, ty, key in rows:
    cols.setdefault(t, []).append((c, ty, key))
tables = sorted(cols)

SPECIAL = {
    "users": {"owner": "id", "private": ["info", "notes", "federaltaxid", "federaldrugid", "state_license_number"],
              "secret": ["google_signin_email"]},
    "users_secure": {"owner": "id", "secret": ["password", "password_history1", "password_history2",
                                               "password_history3", "password_history4", "login_work_area"]},
    "login_mfa_registrations": {"owner": "user_id", "secret": ["var1", "var2"]},
    "patient_data": {"private": ["fname", "lname", "mname", "DOB", "street", "street_line_2", "postal_code", "city",
                                 "drivers_license", "ss", "phone_home", "phone_biz", "phone_contact", "phone_cell",
                                 "email", "email_direct", "mothersname", "guardiansname", "birth_fname", "birth_lname",
                                 "birth_mname", "preferred_name", "billing_note", "occupation", "name_history",
                                 "guardianaddress", "guardiancity", "guardianphone", "guardianworkphone",
                                 "guardianemail", "guardianpostalcode"]},
    # audit trails: no structure worth keeping, so secret (random, same shape)
    "log": {"secret": ["comments", "user_notes", "checksum"]},
    "extended_log": {"secret": ["description"]},
    "api_log": {"secret": ["request_body", "response", "request_url"]},
    "log_comment_encrypt": {"secret": ["checksum", "checksum_api"]},
    "api_token": {"secret": ["token"]},
    "oauth_clients": {"secret": ["client_secret", "registration_token"]},
    "patient_access_onsite": {"secret": ["portal_pwd", "portal_onetime"]},
    "dated_reminders": {"private": ["dr_message_text"]},
}
FREE_TEXT = {"text", "longtext", "mediumtext", "tinytext"}
PHI_NAME = re.compile(r"(^|_)(fname|lname|mname|name|street|address|city|zip|postal_code|phone\w*|email\w*|ss|"
                      r"dob|birth\w*|subscriber_\w+|employer\w*|note|notes|comment|comments|body|reason|"
                      r"description|narrative|message|text)$", re.I)
NOT_PHI = re.compile(r"^(id|uuid|pid|patient_id|encounter|user|username|groupname|type|subtype|category|status|"
                     r"activity|date|title|code|codes|code_type|list_id|form_name|formdir|form_id|provider\w*|"
                     r"facility\w*|deleted|authorized)$", re.I)


def patient_linked(t):
    return any(c in ("pid", "patient_id") for c, _, _ in cols[t])


out_specs = {}
for t in tables:
    if t in SPECIAL:
        s = SPECIAL[t]
        names = {c for c, _, _ in cols[t]}
        for k in ("private", "secret"):
            s[k] = [c for c in s.get(k, []) if c in names]
            if not s[k]:
                s.pop(k)
        out_specs[t] = s
        continue
    if patient_linked(t):
        priv = [c for c, ty, key in cols[t] if key != "PRI" and not NOT_PHI.match(c)
                and (ty in FREE_TEXT or (ty in ("varchar", "char") and PHI_NAME.search(c)))]
        if priv:
            out_specs[t] = {"private": priv}
            continue
    out_specs[t] = {"public": True}


def flow(spec):
    parts = []
    for k, v in spec.items():
        if isinstance(v, bool):
            parts.append("%s: %s" % (k, "true" if v else "false"))
        elif isinstance(v, list):
            parts.append("%s: [%s]" % (k, ", ".join(v)))
        else:
            parts.append("%s: %s" % (k, v))
    return "{%s}" % ", ".join(parts)


n_priv = sum(1 for s in out_specs.values() if "private" in s or "secret" in s)
out = ["# Shadow-data classification of OpenEMR 8.2.0: all %d tables of the installed schema (%d rewritten)."
       % (len(tables), n_priv),
       "# Generated from the installed database by examples/openemr/gen_columns.py, reviewed by hand",
       "# (contracts/product.md §4).",
       "#",
       "# OpenEMR is ACL-based: any clinician with the right ACL may open any patient, so patient data is NOT",
       "# owner-scoped (an owner rule there would flag legitimate access). Patient PHI is still never copied to the",
       "# shadow: identity fields and free text of every patient-linked table (a pid / patient_id column) are",
       "# private without owner (synthetic values, no marker); audit trails are secret (random). Per-user owned data",
       "# (account notes, password hashes, MFA secrets) is owner-scoped by users.id. The rest is reference and",
       "# configuration data, copied verbatim.",
       "users_table: users",
       "user_id_column: id",
       "login_column: username",
       "admin_values: [admin]",
       "tables:"]
for t in tables:
    out.append("  %s: %s" % (t, flow(out_specs[t])))
out += ["routes:", "  user_id: {table: users, column: id}", "why:",
        '  "users.info": "notas internas de la cuenta: sólo el propio usuario y administración"',
        '  "users_secure.password": "hash de contraseña (bcrypt / SHA-512 crypt)"',
        '  "patient_data.fname": "datos personales del paciente: la sombra nunca guarda PHI real"',
        '  "api_log.response": "la API devuelve fichas completas de pacientes"']
open(sys.argv[2], "w", encoding="utf-8", newline="\n").write("\n".join(out) + "\n")
print(len(tables), "tables,", n_priv, "rewritten")
