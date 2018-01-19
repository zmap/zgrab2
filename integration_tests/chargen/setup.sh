#!/usr/bin/env bash

set -e

CONTAINER_TAG="zgrab_inetd"
CONTAINER_NAME="zgrab_inetd"
RUN_ARGS="-td --rm --name $CONTAINER_NAME -p 33007:7 -p 33009:9 -p 33013:13 -p 33019:19 -p 33007:7/udp -p 33009:9/udp -p 33013:13/udp -p 33019:19/udp"

if docker ps --filter "name=$CONTAINER_NAME" | grep -q $CONTAINER_NAME; then
  echo "inetd/setup: Container $CONTAINER_NAME already running -- leaving."
  exit 0
fi

# First attempt: just launch the container
if ! docker run $RUN_ARGS $CONTAINER_TAG; then
    # If it fails, build it from ./container/Dockerfile
    docker build -t $CONTAINER_TAG ./container
    # Try again
    docker run $RUN_ARGS $CONTAINER_TAG
fi
