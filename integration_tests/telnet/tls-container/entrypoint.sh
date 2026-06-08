#!/bin/sh

set -x

# Start stunnel for TLS-wrapped telnet on port 992
stunnel /etc/stunnel/stunnel.conf

# Run plain telnet via inetd in the foreground
while true; do
  if ! inetutils-inetd -d; then
    echo "telnetd exited unexpectedly. Restarting..."
    sleep 1
  fi
done
