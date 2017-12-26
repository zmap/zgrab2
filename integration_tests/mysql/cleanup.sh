#!/usr/bin/env bash

# Keep cleaning up even if something fails
set +e 

# Stop all MySQL containers, but first grab the logs from them

MYSQL_VERSIONS="5.5 5.6 5.7 8.0"

for version in $MYSQL_VERSIONS; do
    CONTAINER_NAME="zgrab_mysql-$version"
    echo "BEGIN DOCKER LOGS FROM $CONTAINER_NAME [{("
    docker logs --tail all $CONTAINER_NAME
    echo ")}] END DOCKER LOGS FROM $CONTAINER_NAME"
    echo "Stopping $CONTAINER_NAME..."
    docker stop $CONTAINER_NAME
    echo "...stopped."
done
