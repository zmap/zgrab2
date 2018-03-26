#!/bin/sh

set -x

while true; do
  if ! /usr/bin/qpsmtpd-prefork --debug --user root; then
    echo "qpsmtpd exited unexpectedly ($?). Restarting..."
    sleep 1
  fi
done
