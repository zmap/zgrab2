#!/bin/bash -e

# NOTE: the 5.5 and 5.6 versions do not have SSL enabled
versions="5.5 5.6 5.7 8.0"

function launch() {
  VERSION=$1
  docker run -itd --rm --name zgrab_mysql-$VERSION -e MYSQL_ALLOW_EMPTY_PASSWORD=true -e MYSQL_LOG_CONSOLE=true mysql:$VERSION
}

function waitFor() {
  VERSION=$1
  CONTAINER_NAME=zgrab_mysql-$VERSION
  echo "mysql/setup: Waiting for mysqld process to come up on $CONTAINER_NAME..."
  while ! (docker exec $CONTAINER_NAME ps -Af | grep mysqld > /dev/null); do
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
