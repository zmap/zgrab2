#!/usr/bin/env bash

set -e
MODULE_DIR=$(dirname $0)
ZGRAB_ROOT=$MODULE_DIR/../..
ZGRAB_OUTPUT=$ZGRAB_ROOT/zgrab-output

# FIXME: Find a way to mount host to container and have it pass CircleCI tests.
# MOUNT_HOST="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )/container"
# MOUNT_CONTAINER="/var/tmp/input/redis"
# EXTRA_DOCKER_ARGS="-v $MOUNT_HOST:$MOUNT_CONTAINER"

mkdir -p $ZGRAB_OUTPUT/redis

echo "redis/test: Tests runner for redis"

configs="default password renamed"

for cfg in $configs; do
    CONTAINER_NAME=zgrab_redis_${cfg}
    echo "redis/test: Testing $CONTAINER_NAME"
    CONTAINER_NAME=$CONTAINER_NAME "$ZGRAB_ROOT/docker-runner/docker-run.sh" redis > "$ZGRAB_OUTPUT/redis/${cfg}-normal.json"
    CONTAINER_NAME=$CONTAINER_NAME "$ZGRAB_ROOT/docker-runner/docker-run.sh" redis --inline > "$ZGRAB_OUTPUT/redis/${cfg}-inline.json"
#     CONTAINER_NAME=$CONTAINER_NAME EXTRA_DOCKER_ARGS=$EXTRA_DOCKER_ARGS "$ZGRAB_ROOT/docker-runner/docker-run.sh" redis --mappings "$MOUNT_CONTAINER/mappings.json" > "$ZGRAB_OUTPUT/redis/${cfg}-normal-mappings.json"
#     CONTAINER_NAME=$CONTAINER_NAME EXTRA_DOCKER_ARGS=$EXTRA_DOCKER_ARGS "$ZGRAB_ROOT/docker-runner/docker-run.sh" redis --inline --mappings "$MOUNT_CONTAINER/mappings.yaml" > "$ZGRAB_OUTPUT/redis/${cfg}-inline-mappings.json"
#     CONTAINER_NAME=$CONTAINER_NAME EXTRA_DOCKER_ARGS=$EXTRA_DOCKER_ARGS "$ZGRAB_ROOT/docker-runner/docker-run.sh" redis --custom-commands "$MOUNT_CONTAINER/extra-commands.json" > "$ZGRAB_OUTPUT/redis/${cfg}-normal-extra.json"
#     CONTAINER_NAME=$CONTAINER_NAME EXTRA_DOCKER_ARGS=$EXTRA_DOCKER_ARGS "$ZGRAB_ROOT/docker-runner/docker-run.sh" redis --inline --custom-commands "$MOUNT_CONTAINER/extra-commands.yaml" > "$ZGRAB_OUTPUT/redis/${cfg}-inline-extra.json"
done

for cfg in $configs; do
    # Dump the docker logs
    CONTAINER_NAME=zgrab_redis_${cfg}
    echo "redis/test: BEGIN docker logs from $CONTAINER_NAME [{("
    docker logs --tail all $CONTAINER_NAME
    echo ")}] END docker logs from $CONTAINER_NAME"
done
