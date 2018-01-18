#!/bin/sh

set -x

while true; do
  if ! /usr/sbin/vsftpd; then
    echo "vsftpd exited unexpectedly. Restarting..."
    sleep 1
  fi
done
