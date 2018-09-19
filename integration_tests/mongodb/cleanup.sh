#!/usr/bin/env bash

# Keep cleaning up even if something fails
set +e

# Stop all MongoDB containers.

versions="3.2.20 3.6.6 4.0.1 4.1.2"

for version in $versions; do
    CONTAINER_NAME="zgrab_mongodb-$version"
    echo "mongodb/cleanup: Stopping $CONTAINER_NAME..."
    docker stop $CONTAINER_NAME
    echo "mongodb/cleanup: ...stopped."
done
