#!/bin/sh

set -x

while true; do
  if ! /usr/sbin/in.telnetd -debug 23; then
    echo "in.telnetd exited unexpectedly. Restarting..."
    sleep 1
  fi
done
