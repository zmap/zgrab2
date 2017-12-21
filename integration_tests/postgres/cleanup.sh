#!/usr/bin/env bash

set +e

echo "Begin tests cleanup for postgres"

function clean() {
  CONTAINER_NAME=$1
  echo "BEGIN DOCKER LOGS FROM $CONTAINER_NAME [{("
  docker logs --tail all $CONTAINER_NAME
  echo ")}] END DOCKER LOGS FROM $CONTAINER_NAME"
  echo "BEGIN POSTGRES LOGS FROM $CONTAINER_NAME [{("
  # TODO HACK FIXME: Hack for MinGW: for some reason, /var/lib/ is being replaced with c:/mingw/msys/1.0/var/lib/, but //var/lib is safe.
  docker exec -t $CONTAINER_NAME cat //var/lib/postgresql/data/pg_log/postgres.log
  echo ")}] END POSTGRES LOGS FROM $CONTAINER_NAME"
  # docker stop $CONTAINER_NAME
}

versions="9.3 9.4 9.5 9.6 10.1"
types="ssl nossl"
for version in $versions; do
  for type in $types; do
    clean "zgrab_postgres_${version}-${type}"
  done
done

echo "Finished tests cleanup for postgres"
