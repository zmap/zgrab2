#!/usr/bin/env bash

set -e

CONTAINER_TAG="zgrab_http"
CONTAINER_NAME="zgrab_http"

if docker ps --filter "name=$CONTAINER_NAME" | grep $CONTAINER_NAME; then
  echo "http/setup: Container $CONTAINER_NAME already running -- nothing to do."
  exit 0
fi

# First attempt to just launch the container
if ! docker run --rm --name $CONTAINER_NAME -td $CONTAINER_TAG; then
    # If it fails, build it from ./container/Dockerfile
    docker build -t $CONTAINER_TAG ./container
    # Try again
    docker run --rm --name $CONTAINER_NAME -td $CONTAINER_TAG
fi

echo -n "http/setup: Waiting on $CONTAINER_NAME to start..."

while ! docker exec -t $CONTAINER_NAME cat //var/log/lighttpd/error.log | grep -q "server started"; do
    echo -n "."
done

sleep 1

echo "...done."
