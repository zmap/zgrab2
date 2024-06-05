#!/usr/bin/env bash

# Keep cleaning up even if something fails
set +e

# Stop all MySQL containers.

VERSIONS="3.12.14 3.13.2"

for version in $MYSQL_VERSIONS; do
    CONTAINER_NAME="zgrab_amqp091-$version"
    echo "amqp091/cleanup: Stopping $CONTAINER_NAME..."
    docker stop $CONTAINER_NAME
    echo "amqp091/cleanup: ...stopped."
done
