#!/bin/bash -e

VERSIONS="3.12.14 3.13.2"

function launch() {
  VERSION=$1
  CONTAINER_NAME="zgrab_amqp091-$VERSION"
  if docker ps --filter "name=$CONTAINER_NAME" | grep -q $CONTAINER_NAME; then
    echo "amqp091/setup: Container $CONTAINER_NAME already running -- skipping launch..."
    return
  fi
  docker run -td --rm --name $CONTAINER_NAME rabbitmq:$VERSION
}

function waitFor() {
  VERSION=$1
  CONTAINER_NAME=zgrab_amqp091-$VERSION
  echo "amqp091/setup: Waiting for $CONTAINER_NAME to become ready..."
  while ! (docker logs --tail all $CONTAINER_NAME | grep -q "started TCP listener on"); do
    echo -n "."
    sleep 1
  done
  for i in $(seq 1 5); do
    echo -n "*"
    sleep 1
  done
  echo "...ok."
}

echo "amqp091/setup: Launching docker containers..."
for version in $VERSIONS; do
  launch $version
done

for version in $VERSIONS; do
  waitFor $version
done
