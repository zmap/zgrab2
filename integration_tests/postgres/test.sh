#!/usr/bin/env bash

set -e

versions="9.3 9.4 9.5 9.6 10.1"
types="ssl nossl"

ZGRAB_ROOT=$(git rev-parse --show-toplevel)
ZGRAB_OUTPUT=$ZGRAB_ROOT/zgrab-output

mkdir -p $ZGRAB_OUTPUT/postgres

function doTest() {
  VERSION=$1
  TYPE=$2
  CONTAINER_NAME=zgrab_postgres_$VERSION-$TYPE
  CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh postgres > $ZGRAB_OUTPUT/postgres/$VERSION-$TYPE.json
  echo "BEGIN DOCKER LOGS FROM $CONTAINER_NAME [{("
  docker logs --tail all $CONTAINER_NAME
  echo ")}] END DOCKER LOGS FROM $CONTAINER_NAME"
  echo "BEGIN POSTGRES LOGS FROM $CONTAINER_NAME [{("
  # TODO: The "//var/lib" is a work-around for MinGW
  docker exec $CONTAINER_NAME cat //var/lib/postgresql/data/pg_log/postgres.log
  echo ")}] END POSTGRES LOGS FROM $CONTAINER_NAME"
}

for version in $versions; do
  for type in $types; do
    doTest $version $type
  done
done
