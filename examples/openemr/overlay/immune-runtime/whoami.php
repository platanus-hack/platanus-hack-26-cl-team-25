<?php

/**
 * Inmune: who owns this session? {"id": <users.id>, "role": "admin"|"user"} or {"id": null}.
 * Read by Inmune's gateway (auth.kind introspect) with the client's own Cookie header. Not part of OpenEMR:
 * it only reads the session OpenEMR already established and asks OpenEMR's ACL whether the user is a
 * super administrator. Never writes the session.
 *
 * ?tokens=1 adds the session's own CSRF tokens (form + API), for the shadow clone's identity profile only:
 * answered only inside a clone (HOST=127.0.0.1, request from the loopback, i.e. from the clone's observer).
 */

$ignoreAuth = true;
$sessionAllowWrite = false;
$_GET['site'] = 'default';
require_once '/var/www/localhost/htdocs/openemr/interface/globals.php';

use OpenEMR\Common\Acl\AclMain;
use OpenEMR\Common\Csrf\CsrfUtils;
use OpenEMR\Common\Session\SessionWrapperFactory;

header('Content-Type: application/json');
header('Cache-Control: no-store');
$session = SessionWrapperFactory::getInstance()->getActiveSession();
$uid = $session->get('authUserID');
$user = $session->get('authUser');
if (empty($uid) || !is_numeric($uid) || !is_string($user) || $user === '') {
    echo json_encode(['id' => null, 'role' => null]);
    exit;
}
$out = ['id' => (int) $uid, 'role' => AclMain::aclCheckCore('admin', 'super', $user) ? 'admin' : 'user'];
$inClone = getenv('HOST') === '127.0.0.1' && ($_SERVER['REMOTE_ADDR'] ?? '') === '127.0.0.1';
if (!empty($_GET['tokens']) && $inClone) {
    $out['csrf_form'] = CsrfUtils::collectCsrfToken($session);
    $out['csrf_api'] = CsrfUtils::collectCsrfToken($session, 'api');
}
echo json_encode($out);
