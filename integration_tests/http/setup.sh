#!/usr/bin/env bash

set -e

CONTAINER_TAG="zgrab_http"
CONTAINER_NAME="zgrab_http"

if docker ps --filter "name=$CONTAINER_NAME" | grep $CONTAINER_NAME; then
  echo "http/setup: Container $CONTAINER_NAME already running -- stopping..."
  docker stop $CONTAINER_NAME
  echo "...stopped."
fi

# First attempt to just launch the container
if ! docker run --rm --name $CONTAINER_NAME -itd $CONTAINER_TAG; then
    # If it fails, build it from ./container/Dockerfile
    docker build -t $CONTAINER_TAG ./container
    # Try again
    docker run --rm --name $CONTAINER_NAME -itd $CONTAINER_TAG
fi
