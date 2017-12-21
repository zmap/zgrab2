#!/usr/bin/env bash
set -e
set -x
WORKDIR=/tmp/postgres_setup
echo "" >> $PGDATA/postgresql.conf
cat $WORKDIR/postgresql.conf.partial >> $PGDATA/postgresql.conf
