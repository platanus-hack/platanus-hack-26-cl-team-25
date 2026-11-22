#!/bin/sh
# Build the static C demo with the toolchain image already present on this host.
# -g: debug info, so the sidecar's native stacks (strace -k + addr2line) resolve to file:line.
# usage: sidecar/examples/c/build.sh OUT_DIR   -> OUT_DIR/app
#   DYNAMIC=1: link the C library dynamically (needs a glibc image to run; strace -k can unwind these frames,
#   while the static glibc build loses them past __internal_syscall_cancel)
set -e
here=$(cd "$(dirname "$0")" && pwd)
out=${1:?output directory}
link=-static; [ -n "$DYNAMIC" ] && link=
docker run --rm --name "p4-cbuild-$$" -v "$here:/src:ro" -v "$out:/out" -u "$(id -u):$(id -g)" immune-cbuild:1 \
  gcc -O2 -g -Wall $link -o /out/app /src/app.c
