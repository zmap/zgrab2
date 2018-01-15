#!/usr/bin/env bash

# Keep cleaning up even if something fails
set +e 

# Stop all MySQL containers.

MYSQL_VERSIONS="5.5 5.6 5.7 8.0"

for version in $MYSQL_VERSIONS; do
    CONTAINER_NAME="zgrab_mysql-$version"
    echo "mysql/cleanup: Stopping $CONTAINER_NAME..."
    docker stop $CONTAINER_NAME
    echo "mysql/cleanup: ...stopped."
done
