#!/bin/sh
# Build the static C demo with the toolchain image already present on this host.
# usage: sidecar/examples/c/build.sh OUT_DIR   -> OUT_DIR/app
set -e
here=$(cd "$(dirname "$0")" && pwd)
out=${1:?output directory}
docker run --rm --name "p4-cbuild-$$" -v "$here:/src:ro" -v "$out:/out" -u "$(id -u):$(id -g)" immune-cbuild:1 \
  gcc -O2 -Wall -static -o /out/app /src/app.c
