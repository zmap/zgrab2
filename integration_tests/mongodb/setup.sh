#!/usr/bin/env bash

set -e
versions="3.2.20 3.6.6 4.0.1 4.1.2"

function launch() {
  VERSION=$1
  CONTAINER_NAME="zgrab_mongodb-$VERSION"
  if docker ps --filter "name=$CONTAINER_NAME" | grep -q $CONTAINER_NAME; then
    echo "mongodb/setup: Container $CONTAINER_NAME already running -- skipping launch..."
    return
  fi
  docker run -td --rm --name $CONTAINER_NAME -d mongo:$VERSION
}

function waitFor() {
  VERSION=$1
  CONTAINER_NAME=zgrab_mongodb-$VERSION
  echo "mongodb/setup: Waiting for $CONTAINER_NAME to become ready..."
  while ! (docker logs --tail all $CONTAINER_NAME | grep -q "waiting for connections"); do
    echo -n "."
    sleep 1
  done
  for i in `seq 1 5`; do
    echo -n "*"
    sleep 1
  done
  echo "...ok."
}

echo "mongodb/setup: Launching docker containers..."
for version in $versions; do
  launch $version
done

for version in $versions; do
  waitFor $version
done
