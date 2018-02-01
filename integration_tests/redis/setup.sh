#!/usr/bin/env bash

echo "redis/setup: Tests setup for redis"

# TODO FIXME -- set the container tag
echo "TODO FIXME:  modify setup.sh to launch the integration test container"
exit 1
# CONTAINER_TAG=FIXME

CONTAINER_NAME="zgrab_redis"

# If the container is already running, use it.
if docker ps --filter "name=$CONTAINER_NAME" | grep -q $CONTAINER_NAME; then
    echo "redis/setup: Container $CONTAINER_NAME already running -- nothing to setup"
    exit 0
fi

# If it is not running, try launching it -- on success, use that. 
echo "redis/setup: Trying to launch $CONTAINER_NAME..."
if ! docker run --rm --name $CONTAINER_NAME -td $CONTAINER_TAG; then
    echo "redis/setup: Building docker image $CONTAINER_TAG..."
    # If it fails, build it from ./container/Dockerfile
    docker build -t $CONTAINER_TAG ./container
    # Try again
    echo "redis/setup: Launching $CONTAINER_NAME..."
    docker run --rm --name $CONTAINER_NAME -td $CONTAINER_TAG
fi
