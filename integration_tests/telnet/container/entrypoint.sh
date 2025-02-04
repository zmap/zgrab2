#!/bin/sh

set -x

while true; do
  if ! inetutils-inetd -d; then
    echo "telnetd exited unexpectedly. Restarting..."
    sleep 1
  fi
done
