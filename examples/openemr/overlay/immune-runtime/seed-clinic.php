<?php

/**
 * Inmune demo data: "Clínica Delta", a fictitious clinic. Every name, date, address and note is synthetic.
 * Run once by seed.sh after OpenEMR's installer, through OpenEMR's own code (users, ACL groups, patients),
 * so the database looks exactly like one an administrator filled in by hand. Idempotent.
 *
 *   admin      Administrators   (created by the installer)
 *   medico1    Physicians       Dra. Marcela Figueroa
 *   medico2    Physicians       Dr. Octavio Llanos
 *   medico3    Physicians       Dra. Antonieta Rivas (TOTP MFA registered; bypassed by CVE-2026-67611;
 *                               deliberately unused by legit.py / attacks.py / the shadow identity, so
 *                               their web logins stay single-factor)
 *   recepcion  Front Office     Pilar Henríquez
 *   paciente1 / paciente2      portal accounts of two synthetic patients
 */

if (php_sapi_name() !== 'cli') {
    exit(1);
}
$_GET['site'] = 'default';
$ignoreAuth = true;
$sessionAllowWrite = true;
require_once '/var/www/localhost/htdocs/openemr/interface/globals.php';

use OpenEMR\BC\ServiceContainer;
use OpenEMR\Common\Acl\AclExtended;
use OpenEMR\Services\PatientService;

function oe_user(string $username, string $fname, string $lname, array $groups, string $password,
                 int $authorized, string $email, string $phone, int $facility): int
{
    $row = sqlQuery("SELECT id FROM users WHERE username = ?", [$username]);
    if (!empty($row['id'])) {
        $id = (int) $row['id'];
    } else {
        $id = (int) sqlInsert(
            "INSERT INTO users (username, password, authorized, fname, lname, active, facility_id, facility, calendar,"
            . " see_auth, email, phone, info, abook_type) VALUES (?, 'NoLongerUsed', ?, ?, ?, 1, ?, 'Clínica Delta', ?, 1, ?, ?, ?, '')",
            [$username, $authorized, $fname, $lname, $facility, $authorized, $email, $phone,
             'Cuenta de demostración (datos sintéticos)']
        );
        sqlStatement("INSERT INTO `groups` (name, user) VALUES ('Default', ?)", [$username]);
    }
    sqlStatement(
        "REPLACE INTO users_secure (id, username, password, last_update_password) VALUES (?, ?, ?, NOW())",
        [$id, $username, password_hash($password, PASSWORD_DEFAULT)]
    );
    AclExtended::setUserAro($groups, $username, $fname, '', $lname);
    return $id;
}

$facility = (int) (sqlQuery("SELECT id FROM facility ORDER BY id LIMIT 1")['id'] ?? 3);
sqlStatement("UPDATE facility SET name = 'Clínica Delta', city = 'Pueblo Delta', phone = '+56 2 2000 0000' WHERE id = ?",
    [$facility]);

// Globals that expose OpenEMR 8.2.0's five CVEs. Every knob below ships hardened-off (or hardened-on) in
// later releases; this is the exact set that makes the stock 8.2.0 image exploitable (docs/openemr.md):
//   rest_api / rest_fhir_api / rest_system_scopes_api / rest_portal_api = 1  the API surfaces exist at all,
//     so the unauthenticated OAuth2 dynamic client registration (/oauth2/default/registration) is reachable,
//     an admin-approved client mints tokens with system-level FHIR scopes via client_credentials + self-signed
//     JWT (CVE-2026-67610), and the portal API answers patient tokens (CVE-2026-67611 impact); these are the
//     same connectors OpenEMR's own CI turns on for the API tests;
//   oauth_password_grant = 3  the OAuth2 password grant for staff users AND portal patients. The grant
//     only checks the TOTP code when the request carries mfa_token (UserRepository.php:111), so valid
//     credentials alone mint an API token and skip the second factor (CVE-2026-67611);
//   portal_onsite_two_enable / portal_onsite_two_basepath = 1  the patient portal is on: its template
//     manager (portal/import_template.php) stores whatever an admin saves except a literal "<?php"
//     (import_template.php:125) and renders it back unencoded, and core session cookies are not HttpOnly
//     by design (src/Common/Session/SessionUtil.php:9), so a poisoned template hijacks sessions
//     (CVE-2026-67612).
// CVE-2026-39932: library/classes/Tree.class.php builds the string passed to eval() (:141) with the
// categories.id column concatenated raw (:119 and :124) — the INT column type is the only guard. The admin
// chain turns it into RCE via an arbitrary-SQL primitive: configuration_import_export=1 enables backup.php's
// "Import Configuration" upload, which executes uploaded SQL, so an admin ALTERs categories.id to VARCHAR,
// INSERTs a row whose id closes the string and calls passthru() (lft/rght inside the root bounds), and any
// page that instantiates CategoryTree (e.g. GET /controller.php?document_category&list) executes it.
// CVE-2026-124471 needs no setting either: interface/billing/sl_eob_invoice.php has no ACL check, so any
// authenticated user can read and modify any encounter's billing (fixed upstream in 8.3.0).
foreach ([
    'rest_api' => '1',
    'rest_fhir_api' => '1',
    'rest_system_scopes_api' => '1',
    'rest_portal_api' => '1',
    'oauth_password_grant' => '3',
    'portal_onsite_two_enable' => '1',
    'portal_onsite_two_basepath' => '1',
    'configuration_import_export' => '1',
] as $name => $value) {
    sqlStatement("UPDATE globals SET gl_value = ? WHERE gl_name = ?", [$value, $name]);
}

$users = [
    'medico1' => oe_user('medico1', 'Marcela', 'Figueroa', ['Physicians'], 'Inmune-medico1-82', 1,
        'm.figueroa@clinica-delta.invalid', '+56 9 0000 0101', $facility),
    'medico2' => oe_user('medico2', 'Octavio', 'Llanos', ['Physicians'], 'Inmune-medico2-82', 1,
        'o.llanos@clinica-delta.invalid', '+56 9 0000 0102', $facility),
    'medico3' => oe_user('medico3', 'Antonieta', 'Rivas', ['Physicians'], 'Inmune-medico3-82', 1,
        'a.rivas@clinica-delta.invalid', '+56 9 0000 0104', $facility),
    'recepcion' => oe_user('recepcion', 'Pilar', 'Henríquez', ['Front Office'], 'Inmune-recepcion-82', 0,
        'recepcion@clinica-delta.invalid', '+56 9 0000 0103', $facility),
];
$admin = (int) (sqlQuery("SELECT id FROM users WHERE username = 'admin'")['id'] ?? 1);
// the installer's admin gets the demo password too (seed.sh passes it; repeated here for idempotence)
sqlStatement("UPDATE users_secure SET password = ? WHERE id = ?",
    [password_hash(getenv('OE_ADMIN_PASS') ?: 'Inmune-admin-82', PASSWORD_DEFAULT), $admin]);

// medico3 registers TOTP MFA through OpenEMR's own crypto, exactly like the reg3 step of
// interface/usergroup/mfa_totp.php:236 (encryptForDatabase + login_mfa_registrations). The web login then
// demands the six-digit code, while the OAuth2 password grant validates it only when the request carries
// mfa_token (UserRepository.php:111): that contrast is the CVE-2026-67611 bypass. medico3 is deliberately
// the only TOTP user: legit.py, attacks.py and the shadow identity log in as medico1/medico2/recepcion,
// whose logins (real and inside clones) must stay single-factor.
$mfaUid = (int) ($users['medico3'] ?? 0);
$mfaRow = $mfaUid ? sqlQuery("SELECT COUNT(*) AS c FROM login_mfa_registrations WHERE user_id = ? AND method = 'TOTP'", [$mfaUid]) : false;
if ($mfaUid && empty($mfaRow['c'])) {
    // fixed 32-character base32 secret (A-Z, 2-7) so the demo is reproducible
    $totpSecret = 'INMUNEMFADEMO2TOTPSECRETA2B3C4D5';
    $cryptoGen = ServiceContainer::getCrypto();
    sqlStatement(
        "INSERT INTO login_mfa_registrations (user_id, method, name, var1, var2) VALUES (?, 'TOTP', 'App Based 2FA', ?, '')",
        [$mfaUid, $cryptoGen->encryptForDatabase($totpSecret)]
    );
    echo "mfa: TOTP registered for medico3 (authenticator-app secret: $totpSecret)\n";
}

$patients = [
    ['Anselmo', 'Bustamante', '1958-03-14', 'Male', 'medico1', 'Hipertensión arterial'],
    ['Rigoberta', 'Cárdenas', '1984-11-02', 'Female', 'medico1', 'Asma bronquial'],
    ['Teodoro', 'Ballesteros', '1972-06-21', 'Male', 'medico1', 'Diabetes mellitus tipo 2'],
    ['Amparo', 'Villagrán', '1990-01-30', 'Female', 'medico1', 'Migraña'],
    ['Celestina', 'Ordóñez', '1965-09-09', 'Female', 'medico2', 'Hipotiroidismo'],
    ['Eusebio', 'Salinas', '1949-12-17', 'Male', 'medico2', 'Insuficiencia cardíaca'],
    ['Genoveva', 'Echeverría', '2001-04-05', 'Female', 'medico2', 'Rinitis alérgica'],
    ['Florencio', 'Maturana', '1977-08-28', 'Male', 'medico2', 'Lumbago crónico'],
];
$service = new PatientService();
$pids = [];
foreach ($patients as $i => [$fname, $lname, $dob, $sex, $doctor, $problem]) {
    $exists = sqlQuery("SELECT pid FROM patient_data WHERE fname = ? AND lname = ?", [$fname, $lname]);
    if (!empty($exists['pid'])) {
        $pids[$i] = (int) $exists['pid'];
        continue;
    }
    $result = $service->insert([
        'fname' => $fname, 'lname' => $lname, 'DOB' => $dob, 'sex' => $sex,
        'street' => 'Avenida Delta ' . (100 + $i), 'city' => 'Pueblo Delta', 'state' => 'RM',
        'postal_code' => '00000', 'country_code' => 'CL', 'phone_home' => '+56 2 2000 1' . sprintf('%03d', $i),
        'email' => strtolower(strtr($fname . '.' . $lname, ['á' => 'a', 'é' => 'e', 'í' => 'i', 'ó' => 'o',
            'ú' => 'u', 'ñ' => 'n', 'Á' => 'A', 'É' => 'E', 'Í' => 'I', 'Ó' => 'O', 'Ú' => 'U', 'Ñ' => 'N']))
            . '@paciente.invalid',
        'providerID' => $users[$doctor], 'ss' => sprintf('900-00-%04d', 1000 + $i),
    ]);
    if (!$result->isValid() || empty($result->getData())) {
        fwrite(STDERR, "patient $fname $lname: " . json_encode($result->getValidationMessages()) . "\n");
        exit(1);
    }
    $pid = (int) $result->getData()[0]['pid'];
    $pids[$i] = $pid;
    sqlStatement("UPDATE patient_data SET providerID = ? WHERE pid = ?", [$users[$doctor], $pid]);
    sqlInsert(
        "INSERT INTO lists (date, type, title, begdate, activity, pid, user, groupname, outcome, comments)"
        . " VALUES (NOW(), 'medical_problem', ?, '2025-01-15', 1, ?, ?, 'Default', 0, ?)",
        [$problem, $pid, $doctor, 'Control periódico (dato sintético)']
    );
    sqlInsert(
        "INSERT INTO pnotes (date, body, pid, user, groupname, activity, authorized, title, assigned_to, message_status)"
        . " VALUES (NOW(), ?, ?, ?, 'Default', 1, 1, 'Unassigned', ?, 'New')",
        ['Nota clínica sintética de ' . $fname . ' ' . $lname . ': evolución estable.', $pid, $doctor, $doctor]
    );
}

// portal patient accounts: two synthetic patients hold active portal credentials (portal_pwd_status=1 and
// no portal_onetime, as if the patient had already verified the account). They are the victims of
// CVE-2026-67612 (a poisoned template renders in their session, and document.cookie is readable) and the
// patient side of the CVE-2026-67611 password grant. Created the way the demographics "Create Portal
// Credentials" flow does: a patient_access_onsite row with a bcrypt portal_pwd plus allow_patient_portal.
$portal_users = [
    'paciente1' => 0,   // Anselmo Bustamante
    'paciente2' => 1,   // Rigoberta Cárdenas
];
foreach ($portal_users as $login => $i) {
    $pid = (int) ($pids[$i] ?? 0);
    if (!$pid) {
        continue;
    }
    $password = 'Inmune-' . $login . '-82';
    sqlStatement("UPDATE patient_data SET allow_patient_portal = 'YES' WHERE pid = ?", [$pid]);
    sqlStatement("DELETE FROM patient_access_onsite WHERE pid = ?", [$pid]);
    sqlStatement(
        "INSERT INTO patient_access_onsite (pid, portal_username, portal_pwd, portal_pwd_status, portal_login_username, portal_onetime)"
        . " VALUES (?, ?, ?, 1, ?, NULL)",
        [$pid, $login, password_hash($password, PASSWORD_DEFAULT), $login]
    );
    echo "portal: $login / $password (patient pid $pid)\n";
}

// private reminders between the two physicians: only the sender and the recipient may read them
$pairs = [['medico1', 'medico2', 'Revisar exámenes pendientes del paciente Bustamante'],
          ['medico2', 'medico1', 'Coordinar interconsulta de cardiología para Salinas']];
foreach ($pairs as [$from, $to, $text]) {
    $exists = sqlQuery("SELECT dr_id FROM dated_reminders WHERE dr_message_text = ?", [$text]);
    if (!empty($exists['dr_id'])) {
        continue;
    }
    $dr = sqlInsert(
        "INSERT INTO dated_reminders (dr_from_ID, dr_message_text, dr_message_sent_date, dr_message_due_date, pid,"
        . " message_priority, message_processed, processed_date, dr_processed_by) VALUES (?, ?, NOW(), CURDATE(), 0, 2, 0, NULL, 0)",
        [$users[$from], $text]
    );
    sqlStatement("INSERT INTO dated_reminders_link (dr_id, to_id) VALUES (?, ?)", [$dr, $users[$to]]);
}

echo "Clínica Delta: " . count($users) . " users, " . count($patients) . " patients\n";
