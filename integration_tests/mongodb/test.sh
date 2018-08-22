#!/usr/bin/env bash

set -e

versions="3.2.20 3.6.6 4.0.1 4.1.2"

MODULE_DIR=$(dirname $0)
ZGRAB_ROOT=$MODULE_DIR/../..
ZGRAB_OUTPUT=$ZGRAB_ROOT/zgrab-output

mkdir -p $ZGRAB_OUTPUT/mongodb


echo "mongodb/test: Tests runner for mongodb"

for version in $versions; do
    CONTAINER_NAME=zgrab_mongodb-${version}
    echo "mongodb/test: Testing $CONTAINER_NAME"
    CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh mongodb > "$ZGRAB_OUTPUT/mongodb/${version}-normal.json"
    # Dump the docker logs
    echo "#{MODULE_NAME}/test: BEGIN docker logs from $CONTAINER_NAME [{("
    docker logs --tail all $CONTAINER_NAME
    echo ")}] END docker logs from $CONTAINER_NAME"
done

