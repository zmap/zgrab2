#!/usr/bin/env bash

echo "pop3/setup: Tests setup for pop3"

CONTAINER_TAG="zgrab_pop3"
CONTAINER_NAME="zgrab_pop3"

# If the container is already running, use it.
if docker ps --filter "name=$CONTAINER_NAME" | grep -q $CONTAINER_NAME; then
    echo "pop3/setup: Container $CONTAINER_NAME already running -- nothing to setup"
    exit 0
fi

# If it is not running, try launching it -- on success, use that. 
echo "pop3/setup: Trying to launch $CONTAINER_NAME..."
if ! docker run --rm --name $CONTAINER_NAME -td $CONTAINER_TAG; then
    echo "pop3/setup: Building docker image $CONTAINER_TAG..."
    # If it fails, build it from ./container/Dockerfile
    docker build -t $CONTAINER_TAG ./container
    # Try again
    echo "pop3/setup: Launching $CONTAINER_NAME..."
    docker run --rm --name $CONTAINER_NAME -td $CONTAINER_TAG
fi
