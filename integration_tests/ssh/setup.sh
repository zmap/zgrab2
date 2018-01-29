#!/usr/bin/env bash

set -e

CONTAINER_TAG="zgrab_ssh"
CONTAINER_NAME="zgrab_ssh"

# TODO FIXME: find a pre-built container with sshd already running? This works, but if it has to build the container image, the apt-get update is very slow.

if docker ps --filter "name=$CONTAINER_NAME" | grep -q $CONTAINER_NAME; then
  echo "ssh/setup: Container $CONTAINER_NAME already running -- nothing to do."
  exit 0
fi

# First attempt to just launch the container
if ! docker run --rm --name $CONTAINER_NAME -td $CONTAINER_TAG; then
    # If it fails, build it from ./container/Dockerfile
    docker build -t $CONTAINER_TAG ./container
    # Try again
    docker run --rm --name $CONTAINER_NAME -td $CONTAINER_TAG
fi
