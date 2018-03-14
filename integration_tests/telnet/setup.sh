#!/usr/bin/env bash

echo "telnet/setup: Tests setup for telnet"

CONTAINER_TAG="zgrab_telnet"

CONTAINER_NAME="zgrab_telnet"

# If the container is already running, use it.
if docker ps --filter "name=$CONTAINER_NAME" | grep -q $CONTAINER_NAME; then
    echo "telnet/setup: Container $CONTAINER_NAME already running -- nothing to setup"
    exit 0
fi

# If it is not running, try launching it -- on success, use that. 
echo "telnet/setup: Trying to launch $CONTAINER_NAME..."
if ! docker run --rm --name $CONTAINER_NAME -td $CONTAINER_TAG; then
    echo "telnet/setup: Building docker image $CONTAINER_TAG..."
    # If it fails, build it from ./container/Dockerfile
    docker build -t $CONTAINER_TAG ./container
    # Try again
    echo "telnet/setup: Launching $CONTAINER_NAME..."
    docker run --rm --name $CONTAINER_NAME -td $CONTAINER_TAG
fi
