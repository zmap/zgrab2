#!/usr/bin/env bash

set -e

CONTAINER_TAG="zgrab_http"
CONTAINER_NAME="zgrab_http"

# First attempt to just launch the container
if ! docker run --rm --name $CONTAINER_NAME -itd $CONTAINER_TAG; then
    # If it fails, build it from ./container/Dockerfile
    docker build -t $CONTAINER_TAG ./container
    # Try again
    docker run --rm --name $CONTAINER_NAME -itd $CONTAINER_TAG
fi
