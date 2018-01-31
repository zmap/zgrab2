#!/usr/bin/env bash

set -e

versions="openntp 4.2.6"

CONTAINER_TAG="zgrab_ntp"
for version in $versions; do
    CONTAINER_NAME="zgrab_ntp_$version"

    echo "ntp/setup: Setting up $CONTAINER_NAME"

    DOCKER_RUN_ARGS="--privileged -itd --rm --name $CONTAINER_NAME"

    if docker ps --filter "name=$CONTAINER_NAME" | grep -q $CONTAINER_NAME; then
        echo "ntp/setup: Container $CONTAINER_NAME already running -- skipping."
    else
        # First attempt: just launch the container
        if ! docker run $DOCKER_RUN_ARGS "$CONTAINER_TAG:$version"; then
            # If it fails, build it from ./container/Dockerfile
            echo "ntp/setup: Building $CONTAINER_TAG:$version from ./container-$version"
            docker build -t "$CONTAINER_TAG:$version" ./container-$version
            # Try again
            docker run $DOCKER_RUN_ARGS $CONTAINER_TAG:$version
        fi
    fi
done

echo -n "ntp/setup: Waiting on zgrab_ntp_openntp..."
while ! docker logs --tail all zgrab_ntp_openntp | grep -q "ntp engine ready"; do
    echo -n "."
done
echo "...done."

echo -n "ntp/setup: Waiting on zgrab_ntp_4.2.6..."
while ! docker logs --tail all zgrab_ntp_4.2.6 | grep -q "listen"; do
    echo -n "."
done

sleep 1

echo "...done."
