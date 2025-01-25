#!/usr/bin/env bash

echo "pptp/setup: Tests setup for pptp"

CONTAINER_TAG="mobtitude/vpn-pptp"
CONTAINER_NAME="zgrab_pptp" 

# If the container is already running, use it.
if docker ps --filter "name=$CONTAINER_NAME" | grep -q $CONTAINER_NAME; then
    echo "pptp/setup: Container $CONTAINER_NAME already running -- nothing to setup"
    exit 0
fi

DOCKER_RUN_FLAGS="--rm --privileged --name $CONTAINER_NAME -td -v ./chap-secrets:/etc/ppp/chap-secrets"

# If it is not running, try launching it -- on success, use that. 
echo "pptp/setup: Trying to launch $CONTAINER_NAME..."
if ! docker run $DOCKER_RUN_FLAGS $CONTAINER_TAG; then
    echo "failed"
    # echo "pptp/setup: Building docker image $CONTAINER_TAG..."
    # # If it fails, build it from ./container/Dockerfile
    # docker build -t $CONTAINER_TAG ./container
    # # Try again
    # echo "pptp/setup: Launching $CONTAINER_NAME..."
    # docker run $DOCKER_RUN_FLAGS $CONTAINER_TAG
fi
