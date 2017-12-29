#!/usr/bin/env bash

set +e

echo "postgres/cleanup: Begin tests cleanup for postgres"

function clean() {
  CONTAINER_NAME=$1
  docker stop $CONTAINER_NAME
}

versions="9.3 9.4 9.5 9.6 10.1"
types="ssl nossl"
for version in $versions; do
  for type in $types; do
    clean "zgrab_postgres_${version}-${type}"
  done
done

echo "postgres/cleanup: Finished tests cleanup for postgres"
