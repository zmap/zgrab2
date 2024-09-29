#!/usr/bin/env bash

echo "socks5/setup: Tests setup for socks5"

CONTAINER_TAG="3proxy/3proxy"
CONTAINER_NAME="zgrab_socks5"

# If the container is already running, use it.
if docker ps --filter "name=$CONTAINER_NAME" | grep -q $CONTAINER_NAME; then
    echo "socks5/setup: Container $CONTAINER_NAME already running -- nothing to setup"
    exit 0
fi

DOCKER_RUN_FLAGS="--rm --name $CONTAINER_NAME -e "PROXY_USER=user" -e "PROXY_PASS=password" -v ./3proxy.cfg:/etc/3proxy/3proxy.cfg -td"

# If it is not running, try launching it -- on success, use that. 
echo "socks5/setup: Trying to launch $CONTAINER_NAME..."
if ! docker run $DOCKER_RUN_FLAGS $CONTAINER_TAG; then
    echo "failed"
    # echo "socks5/setup: Building docker image $CONTAINER_TAG..."
    # # If it fails, build it from ./container/Dockerfile
    # docker build -t $CONTAINER_TAG ./container
    # # Try again
    # echo "socks5/setup: Launching $CONTAINER_NAME..."
    # docker run $DOCKER_RUN_FLAGS $CONTAINER_TAG
fi
