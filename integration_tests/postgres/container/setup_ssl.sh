#!/usr/bin/env bash
set -e
set -x
WORKDIR=/tmp/postgres_setup

# Generate a self-signed key/certificate
openssl req -new -x509 -nodes -keyout $WORKDIR/server.p8 -out $WORKDIR/server.crt -subj "/CN=localhost"

# Get the private key in passwordless PEM format for use by postgres
openssl rsa -in $WORKDIR/server.p8 -out $WORKDIR/server.key

chown postgres:postgres $WORKDIR/server.*
chmod 0600 $WORKDIR/server.key
chmod 0644 $WORKDIR/server.crt

cp $WORKDIR/server.key $PGDATA
cp $WORKDIR/server.crt $PGDATA

echo "" >> $PGDATA/postgresql.conf

# Attach the SSL + Logging config to the end of the main postgresql.conf file
cat $WORKDIR/postgresql.conf.partial >> $PGDATA/postgresql.conf
