#!/usr/bin/env bash

set -e

echo "redis/setup: Tests setup for redis"

CONTAINER_TAG="zgrab_redis"

configs="default password renamed"

for cfg in $configs; do
    CONTAINER_NAME="zgrab_redis_$cfg"

    RUN_ARGS="--rm --name $CONTAINER_NAME -td $CONTAINER_TAG redis-server //usr/local/etc/redis/${cfg}.conf"
    # If the container is already running, use it.
    if docker ps --filter "name=$CONTAINER_NAME" | grep -q $CONTAINER_NAME; then
        echo "redis/setup: Container $CONTAINER_NAME already running -- nothing to setup"
        exit 0
    fi

    # If it is not running, try launching it -- on success, use that.
    echo "redis/setup: Trying to launch $CONTAINER_NAME..."
    if ! docker run $RUN_ARGS; then
        echo "redis/setup: Building docker image $CONTAINER_TAG..."
        # If it fails, build it from ./container/Dockerfile
        docker build -t $CONTAINER_TAG ./container
        # Try again
        echo "redis/setup: Launching $CONTAINER_NAME..."
        docker run $RUN_ARGS
    fi
done
