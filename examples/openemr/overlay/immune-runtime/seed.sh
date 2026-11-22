#!/bin/sh
# Demo prod database (data.demo_mysql.seed_command, run once by `immune up` in the t0 image with a writable
# filesystem): OpenEMR's own installer (auto_configure.php -> Installer::quick_install) against the empty
# database, then the synthetic "Clínica Delta" (immune-runtime/seed-clinic.php, through OpenEMR's own code).
# Env: MYSQL_HOST MYSQL_PORT MYSQL_USER MYSQL_PASS MYSQL_DATABASE (database.env), IMMUNE_DB_ROOT_PASSWORD.
set -eu
OE=/var/www/localhost/htdocs/openemr
cd "$OE"

echo "seed: waiting for ${MYSQL_HOST}:${MYSQL_PORT}"
i=0
until mariadb-admin ping --skip-ssl -h "$MYSQL_HOST" -P "$MYSQL_PORT" -u "$MYSQL_USER" -p"$MYSQL_PASS" --silent 2>/dev/null; do
    i=$((i + 1)); [ "$i" -gt 120 ] && { echo "seed: database unreachable" >&2; exit 1; }; sleep 1
done

# the installer needs an unconfigured site and a writable documents tree
mkdir -p /tmp/openemr/documents /tmp/openemr/sessions /tmp/openemr/php-tmp
cp -a /immune/documents-template/. /tmp/openemr/documents/
chmod 0644 sites/default/sqlconf.php
cp /immune/installer/sqlconf.unconfigured.php sites/default/sqlconf.php

if [ "$(mariadb --skip-ssl -N -h "$MYSQL_HOST" -P "$MYSQL_PORT" -u "$MYSQL_USER" -p"$MYSQL_PASS" "$MYSQL_DATABASE" \
        -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'globals'")" = "0" ]; then
    echo "seed: installing OpenEMR 8.2.0 schema"
    php -d memory_limit=1024M /immune/installer/auto_configure.php -f \
        "server=${MYSQL_HOST} port=${MYSQL_PORT} login=${MYSQL_USER} pass=${MYSQL_PASS} dbname=${MYSQL_DATABASE} root=root rootpass=${IMMUNE_DB_ROOT_PASSWORD} loginhost=% iuser=admin iuname=Administrador iuserpass=${OE_ADMIN_PASS:-Inmune-admin-82} no_root_db_access=1"
fi
cp /immune/sqlconf.php sites/default/sqlconf.php

echo "seed: Clínica Delta (synthetic data)"
php -d memory_limit=512M /immune/seed-clinic.php
echo "seed: done"
