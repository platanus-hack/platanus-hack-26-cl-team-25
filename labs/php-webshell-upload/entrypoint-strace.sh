#!/bin/sh
# Trace execve across all Apache workers; timestamps let the oracle window by request.
strace -f -tt -e trace=execve -o /tmp/trace.log apache2-foreground
