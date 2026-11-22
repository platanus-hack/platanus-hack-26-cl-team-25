#!/bin/sh
# Container start (as `apache`, read-only root filesystem): the writable tree under /tmp, then Apache in the
# foreground on ${HOST}:8080 (HOST is app.bind_env: 0.0.0.0 in prod, 127.0.0.1 in shadow clones, so a clone
# is only reachable through its observer).
set -eu
umask 0022   # the observer (another uid, no DAC override) reads the call traces
mkdir -p /tmp/openemr/sessions /tmp/openemr/php-tmp /tmp/openemr/documents
cp -a /immune/documents-template/. /tmp/openemr/documents/
# call traces of the shadow-only -trace image (removed by the observer between requests)
mkdir -p /tmp/immune-trace && chmod 0777 /tmp/immune-trace
export IMMUNE_LISTEN="${HOST:-0.0.0.0}:${PORT:-8080}"
exec /usr/sbin/httpd -f /immune/httpd.conf -DFOREGROUND
