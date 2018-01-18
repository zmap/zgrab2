#!/usr/bin/env bash

set -e

CONTAINER_TAG="zgrab_ftp"
CONTAINER_NAME="zgrab_ftp"

# TODO FIXME: find a pre-built container with ftpd already running? This works, but if it has to build the container image, the apt-get update can be very slow.

if docker ps --filter "name=$CONTAINER_NAME" | grep $CONTAINER_NAME; then
  echo "ftp/setup: Container $CONTAINER_NAME already running -- stopping..."
  docker stop $CONTAINER_NAME
  echo "...stopped."
fi

# First attempt: just launch the container
if ! docker run --rm --name $CONTAINER_NAME -itd $CONTAINER_TAG; then
    # If it fails, build it from ./container/Dockerfile
    docker build -t $CONTAINER_TAG ./container
    # Try again
    docker run --rm --name $CONTAINER_NAME -itd $CONTAINER_TAG
fi
