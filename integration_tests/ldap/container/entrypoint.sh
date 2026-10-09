#!/bin/sh

set -x

# Start slapd briefly to apply TLS configuration
slapd -h "ldap:/// ldapi:///" -u openldap -g openldap
sleep 2

# Apply TLS configuration
ldapmodify -Y EXTERNAL -H ldapi:/// -f /etc/ldap/tls-config.ldif 2>&1 || true

# Stop the temporary slapd
kill $(cat /var/run/slapd/slapd.pid 2>/dev/null) 2>/dev/null || true
sleep 1

# Start slapd with both LDAP (389) and LDAPS (636) listeners
while true; do
    slapd -h "ldap:/// ldaps:/// ldapi:///" -u openldap -g openldap -d 256
    echo "slapd exited unexpectedly. Restarting..."
    sleep 1
done
