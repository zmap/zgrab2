#!/usr/bin/env bash
set -e
set -x
WORKDIR=/tmp/postgres_setup
echo "" >> $PGDATA/postgresql.conf

# Attach the SSL + Logging config to the end of the main postgresql.conf file
cat $WORKDIR/postgresql.conf.partial >> $PGDATA/postgresql.conf
