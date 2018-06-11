#!/bin/sh

set -x

while true; do
#FIXME: Determine whether -f or -F is ideal, and whether any other options are needed
  if ! /usr/sbin/cupsd -f; then
    echo "cupsd exited unexpectedly. Restarting..."
    sleep 1
  fi
done
