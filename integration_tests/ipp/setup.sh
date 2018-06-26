#!/usr/bin/env bash

echo "ipp/setup: Tests setup for ipp"

versions="cups cups-tls"

CONTAINER_TAG="zgrab_ipp"
for version in $versions; do
    CONTAINER_NAME="zgrab_ipp_$version"

    echo "ipp/setup: Setting up $CONTAINER_NAME"

    DOCKER_RUN_FLAGS="--rm --name $CONTAINER_NAME -td"

    # If the container is already running, use it.
    if docker ps --filter "name=$CONTAINER_NAME" | grep -q $CONTAINER_NAME; then
        echo "ipp/setup: Container $CONTAINER_NAME already running -- nothing to setup"
    else
        if ! docker run $DOCKER_RUN_FLAGS "$CONTAINER_TAG:$version"; then
            echo "ipp/setup: Building docker image $CONTAINER_TAG..."
            # If it fails, build it from ./container/Dockerfile
            docker build -t "$CONTAINER_TAG:$version" ./container-$version
            # Try again
            echo "ipp/setup: Launching $CONTAINER_NAME..."
            docker run $DOCKER_RUN_FLAGS $CONTAINER_TAG:$version
        fi
    fi
    # Add file printer so that CUPS-get-printers response is populated
    docker exec $CONTAINER_NAME lpadmin -p null -E -v file:/dev/null
done