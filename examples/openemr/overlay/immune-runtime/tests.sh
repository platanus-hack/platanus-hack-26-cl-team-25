#!/bin/sh
# tests.command for the pipeline's `tests` gate (run in the app image, the patched release mounted over the
# docroot). The official image ships OpenEMR without its development dependencies (no PHPUnit), so the
# gate checks what can be checked inside it: every PHP file that differs from the t0 image must parse
# (php -l), and OpenEMR must still bootstrap (interface/globals.php in CLI). Output is TAP-like so the
# gate can count it: "# tests N", "# pass N", "# fail N", "not ok - <file>".
set -u
OE=/var/www/localhost/htdocs/openemr
cd "$OE"
changed=$(sha1sum -c /immune/t0.sha1 2>/dev/null | sed -n 's/: FAILED$//p')
n=0; fail=0
for f in $changed; do
    n=$((n + 1))
    if out=$(php -l "$f" 2>&1); then
        echo "ok $n - php -l $f"
    else
        fail=$((fail + 1)); echo "not ok $n - php -l $f"; echo "$out" | sed 's/^/# /'
    fi
done
n=$((n + 1))
if php -d display_errors=stderr -r '$_GET["site"]="default"; $ignoreAuth=true; require "interface/globals.php"; echo "bootstrap ok\n";' >/tmp/bootstrap.out 2>&1 \
        && grep -q "bootstrap ok" /tmp/bootstrap.out; then
    echo "ok $n - OpenEMR bootstraps (interface/globals.php)"
else
    fail=$((fail + 1)); echo "not ok $n - OpenEMR bootstraps (interface/globals.php)"; tail -5 /tmp/bootstrap.out | sed 's/^/# /'
fi
echo "# tests $n"
echo "# pass $((n - fail))"
echo "# fail $fail"
[ "$fail" -eq 0 ]
