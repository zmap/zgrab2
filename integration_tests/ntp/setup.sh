#!/usr/bin/env bash

set -e

CONTAINER_TAG="zgrab_ntp"
CONTAINER_NAME="zgrab_ntp"

DOCKER_RUN_ARGS="--privileged -itd --rm --name $CONTAINER_NAME"

if docker ps --filter "name=$CONTAINER_NAME" | grep -q $CONTAINER_NAME; then
  echo "ntp/setup: Container $CONTAINER_NAME already running -- stopping..."
  docker stop $CONTAINER_NAME
  echo "...stopped."
fi

# First attempt: just launch the container
if ! docker run $DOCKER_RUN_ARGS $CONTAINER_TAG; then
    # If it fails, build it from ./container/Dockerfile
    docker build -t $CONTAINER_TAG ./container
    # Try again
    docker run $DOCKER_RUN_ARGS $CONTAINER_TAG
fi
