#!/bin/sh
# strace is PID1 so `docker stop` (SIGTERM) reaches it directly; strace flushes its output
# buffer and exits cleanly, after which the full trace is read with `docker cp`.
: > /tmp/trace.log
exec strace -f -ttt -s 256 -e trace=open,openat,execve,connect -o /tmp/trace.log httpd -X -D FOREGROUND
