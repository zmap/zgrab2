#!/usr/bin/env bash

echo "ipp/setup: Tests setup for ipp"

CONTAINER_TAG="zgrab_ipp"
CONTAINER_NAME="zgrab_ipp"

# If the container is already running, use it.
if docker ps --filter "name=$CONTAINER_NAME" | grep -q $CONTAINER_NAME; then
    echo "ipp/setup: Container $CONTAINER_NAME already running -- nothing to setup"
    exit 0
fi

DOCKER_RUN_FLAGS="--rm --name $CONTAINER_NAME -td"

# If it is not running, try launching it -- on success, use that. 
echo "ipp/setup: Trying to launch $CONTAINER_NAME..."
if ! docker run $DOCKER_RUN_FLAGS $CONTAINER_TAG; then
    echo "ipp/setup: Building docker image $CONTAINER_TAG..."
    # If it fails, build it from ./container/Dockerfile
    docker build -t $CONTAINER_TAG ./container
    # Try again
    echo "ipp/setup: Launching $CONTAINER_NAME..."
    docker run $DOCKER_RUN_FLAGS $CONTAINER_TAG
fi
