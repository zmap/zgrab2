#!/bin/bash -e

# NOTE: the 5.5 and 5.6 versions do not have SSL enabled
versions="5.5 5.6 5.7 8.0"

function launch() {
  VERSION=$1
  CONTAINER_NAME="zgrab_mysql-$VERSION"
  if docker ps --filter "name=$CONTAINER_NAME" | grep -q $CONTAINER_NAME; then
    echo "mysql/setup: Container $CONTAINER_NAME already running -- skipping launch..."
    return
  fi
  docker run -td --rm --name $CONTAINER_NAME -e MYSQL_ALLOW_EMPTY_PASSWORD=true -e MYSQL_LOG_CONSOLE=true mysql:$VERSION
}

function waitFor() {
  VERSION=$1
  CONTAINER_NAME=zgrab_mysql-$VERSION
  echo "mysql/setup: Waiting for $CONTAINER_NAME to become ready..."
  while ! (docker logs --tail all $CONTAINER_NAME | grep -q "ready for connections."); do
    echo -n "."
    sleep 1
  done
  for i in `seq 1 5`; do
    echo -n "*"
    sleep 1
  done
  echo "...ok."
}

echo "mysql/setup: Launching docker containers..."
for version in $versions; do
  launch $version
done

for version in $versions; do
  waitFor $version
done
