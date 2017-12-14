#!/bin/bash

# Launch a MySQL container with $MYSQL_VERSION, an root empty password, console logging, and host:$MYSQL_PORT forwarded to container:3306

if [ -z $CONTAINER_NAME ] || [ -z $MYSQL_PORT ] || [ -z $MYSQL_VERSION ]; then
    echo "Must provide CONTAINER_NAME, MYSQL_PORT and MYSQL_VERSION"
    exit 1
fi

set -x
docker run -itd -p $MYSQL_PORT:3306 --rm --name $CONTAINER_NAME -e MYSQL_ALLOW_EMPTY_PASSWORD=true -e MYSQL_LOG_CONSOLE=true $* mysql:$MYSQL_VERSION
set +x

exit 0
