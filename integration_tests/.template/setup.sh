#!/usr/bin/env bash

echo "#{MODULE_NAME}/setup: Tests setup for #{MODULE_NAME}"

CONTAINER_TAG="zgrab_#{MODULE_NAME}"
CONTAINER_NAME="zgrab_#{MODULE_NAME}"

# If the container is already running, use it.
if docker ps --filter "name=$CONTAINER_NAME" | grep -q $CONTAINER_NAME; then
    echo "#{MODULE_NAME}/setup: Container $CONTAINER_NAME already running -- nothing to setup"
    exit 0
fi

DOCKER_RUN_FLAGS="--rm --name $CONTAINER_NAME -td"

# If it is not running, try launching it -- on success, use that. 
echo "#{MODULE_NAME}/setup: Trying to launch $CONTAINER_NAME..."
if ! docker run $DOCKER_RUN_FLAGS $CONTAINER_TAG; then
    echo "#{MODULE_NAME}/setup: Building docker image $CONTAINER_TAG..."
    # If it fails, build it from ./container/Dockerfile
    docker build -t $CONTAINER_TAG ./container
    # Try again
    echo "#{MODULE_NAME}/setup: Launching $CONTAINER_NAME..."
    docker run $DOCKER_RUN_FLAGS $CONTAINER_TAG
fi
