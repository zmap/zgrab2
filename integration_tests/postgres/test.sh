#!/usr/bin/env bash

set -e

ports_ssl=()
ports_nossl=()
versions=()

# FIXME: Is the travis host on the same network as the docker containers?
# If so, we can --expose the ports instead of forwarding them to the host.
versions+=("9.3")
ports_ssl+=("5432")
ports_nossl+=("5433")

versions+=("9.4")
ports_ssl+=("15432")
ports_nossl+=("15433")

versions+=("9.5")
ports_ssl+=("25432")
ports_nossl+=("25433")

versions+=("9.6")
ports_ssl+=("35432")
ports_nossl+=("35433")

versions+=("10.1")
ports_ssl+=("45432")
ports_nossl+=("45433")

if [ -x $ZGRAB_ROOT ]; then
  ZGRAB_ROOT=$(dirname $0)/../..
fi

if [ -x $ZGRAB_OUTPUT ]; then
  ZGRAB_OUTPUT=$ZGRAB_ROOT/zgrab-output
fi

mkdir -p $ZGRAB_OUTPUT/postgres

function doTest() {
  VERSION=$1
  TYPE=$2
  PORT=$3
  CONTAINER_NAME=zgrab_postgres_$VERSION-$TYPE
  CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh postgres > $ZGRAB_OUTPUT/postgres/$VERSION-$TYPE.json
  echo "BEGIN DOCKER LOGS FROM $CONTAINER_NAME [{("
  docker logs --tail all $CONTAINER_NAME
  echo ")}] END DOCKER LOGS FROM $CONTAINER_NAME"
  echo "BEGIN POSTGRES LOGS FROM $CONTAINER_NAME [{("
  # TODO: The "//var/lib" is a work-around for MinGW
  docker exec -t $CONTAINER_NAME cat //var/lib/postgresql/data/pg_log/postgres.log
  echo ")}] END POSTGRES LOGS FROM $CONTAINER_NAME"
}

for i in `seq 1 ${#versions[@]}`; do
  version=${versions[i-1]}
  port_ssl=${ports_ssl[i-1]}
  port_nossl=${ports_nossl[i-1]}
  doTest $version "ssl" $port_ssl
  doTest $version "nossl" $port_nossl
done

for version in $versions; do
  for type in $types; do
    doTest $version $type
  done
done
