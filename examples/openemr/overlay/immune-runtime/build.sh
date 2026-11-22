#!/bin/sh
# Image build step (as root, once): prepares the official OpenEMR 8.2.0 image for a read-only root
# filesystem, no capabilities and a non-root Apache on :8080. Never touches OpenEMR's PHP sources.
set -eu
OE=/var/www/localhost/htdocs/openemr

grep -q "^\$v_major = '8';" "$OE/version.php"
grep -q "^\$v_minor = '2';" "$OE/version.php"
grep -q "^\$v_patch = '0';" "$OE/version.php"

# The installer is only used by the demo seed (immune-runtime/seed.sh); the setup scripts leave the docroot,
# exactly as the official entrypoint does after its first configuration.
mkdir -p /immune/installer
cp "$OE/auto_configure.php" /immune/installer/auto_configure.php
chmod 0644 /immune/installer/auto_configure.php   # the official image keeps it at mode 000
rm -f "$OE/admin.php" "$OE/setup.php" "$OE/auto_configure.php" "$OE/acl_upgrade.php" "$OE/sql_patch.php" \
      "$OE/sql_upgrade.php" "$OE/ippf_upgrade.php"

# Database connection from the environment (MYSQL_HOST / MYSQL_PORT / MYSQL_USER / MYSQL_PASS /
# MYSQL_DATABASE): prod, every shadow clone and the judge give the same image different databases.
cp "$OE/sites/default/sqlconf.php" /immune/installer/sqlconf.unconfigured.php
chmod 0644 /immune/installer/sqlconf.unconfigured.php
install -o apache -g apache -m 0444 /immune/sqlconf.php "$OE/sites/default/sqlconf.php"

# sites/default/documents is OpenEMR's only runtime-writable tree (compiled templates, logs, keys,
# uploads): it lives under /tmp, re-created from this template on every start.
mv "$OE/sites/default/documents" /immune/documents-template
ln -s /tmp/openemr/documents "$OE/sites/default/documents"
chown -h apache:apache "$OE/sites/default/documents"

# PHP: sessions and temporary files under /tmp, errors to the container log.
PHPINI=$(php --ini | sed -n 's/^Scan for additional .ini files in: *//p' | tr -d '"')
cp /immune/php-immune.ini "$PHPINI/zz-immune.ini"

# the code (not sites/) world-readable: the shadow clone's observer, another uid without DAC override, scans
# the app's string constants (sql taint rule 3); the official image keeps the docroot at 0700 apache.
# The observer skips dependencies. Leave their permissions intact and skip symlinks and entries already readable.
find "$OE" -type d \( -path "$OE/sites" -o -name vendor -o -name node_modules \) -prune -o ! -type l \
    \( ! -perm -0444 -o \( ! -perm -0111 \( -type d -o -perm -0100 -o -perm -0010 -o -perm -0001 \) \) \) \
    -exec chmod a+rX {} +

# checksums of the release's PHP sources as built: tests.sh lints exactly the files a patch changed
( cd "$OE" && find interface library src apis portal controllers oauth2 controller.php index.php -name '*.php' -type f \
    -print0 | xargs -0 sha1sum ) > /immune/t0.sha1
chmod 0644 /immune/t0.sha1

chmod 0755 /immune /immune/*.sh
chmod 0644 /immune/*.conf /immune/*.ini /immune/*.php /immune/*.sql 2>/dev/null || true
chown -R apache:apache /immune/documents-template
