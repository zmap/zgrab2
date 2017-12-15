#!/bin/bash -e
SSH_PORT=33022
CONTAINER_TAG="sshtest"
CONTAINER_NAME="sshtest"

# TODO FIXME: find a pre-built container with sshd already running? This works, but if it has to build the container image, the apt-get update is very slow.

# First attempt to just launch the container
if ! docker run --rm --name $CONTAINER_NAME -itd -p $SSH_PORT:22 $CONTAINER_TAG; then
    # If it fails, build it from ./container/Dockerfile
    docker build -t $CONTAINER_TAG ./container
    # Try again
    docker run --rm --name $CONTAINER_NAME -itd -p $SSH_PORT:22 $CONTAINER_TAG
fi

# TODO: Wait on port 22?
