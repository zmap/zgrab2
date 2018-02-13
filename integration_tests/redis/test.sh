#!/usr/bin/env bash

set -e
MODULE_DIR=$(dirname $0)
ZGRAB_ROOT=$MODULE_DIR/../..
ZGRAB_OUTPUT=$ZGRAB_ROOT/zgrab-output

mkdir -p $ZGRAB_OUTPUT/redis

echo "redis/test: Tests runner for redis"

configs="default password renamed"

for cfg in $configs; do
    CONTAINER_NAME=zgrab_redis_${cfg}
    echo "redis/test: Testing $CONTAINER_NAME"
    CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh redis > "$ZGRAB_OUTPUT/redis/${cfg}-normal.json"
    CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh redis --inline > "$ZGRAB_OUTPUT/redis/${cfg}-inline.json"
done

for cfg in $configs; do
    # Dump the docker logs
    CONTAINER_NAME=zgrab_redis_${cfg}
    echo "redis/test: BEGIN docker logs from $CONTAINER_NAME [{("
    docker logs --tail all $CONTAINER_NAME
    echo ")}] END docker logs from $CONTAINER_NAME"
done
