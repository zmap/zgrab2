#!/bin/bash

if [ -z $CONTAINER_NAME ] || [ -z $MYSQL_PORT ]; then
    echo "Must provide CONTAINER_NAME and MYSQL_PORT"
    exit 1
fi

echo "Waiting for mysqld process to come up on $CONTAINER_NAME..."
while ! (docker exec $CONTAINER_NAME ps -Af | grep mysqld > /dev/null); do
    echo -n "."
    sleep 1
done

echo "...mysqld is up, waiting for $MYSQL_PORT..."
while ! (nc -z localhost $MYSQL_PORT); do
    echo -n "."
    sleep 1
done

echo "...$MYSQL_PORT is up, waiting for data..."
while ! (output=$(nc -w 5 localhost $MYSQL_PORT) && [ ${#output} -gt 0 ]); do
    echo -n "."
    sleep 1
done

echo "Received data on port $MYSQL_PORT. Container $CONTAINER_NAME is ready."

exit 0
