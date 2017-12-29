#!/usr/bin/env bash

set -e

versions="9.3 9.4 9.5 9.6 10.1"
types="ssl nossl"

function doSetup() {
  VERSION=$1
  TYPE=$2
  CONTAINER_NAME="zgrab_postgres_${VERSION}-${TYPE}"
  IMAGE_TAG="zgrab_postgres:${VERSION}-${TYPE}"
  if grep "$IMAGE_TAG" < images.tmp > /dev/null && [ -x $REBUILD ]; then
    echo "postgres/setup: docker image $IMAGE_TAG already exists -- skipping."
  else
    echo "postgres/setup: docker image $IMAGE_TAG does not exist -- creating..."
    ./build.sh $TYPE $VERSION
  fi
  if docker ps --filter "name=$CONTAINER_NAME" | grep $CONTAINER_NAME; then
    echo "postgres/setup: Container $CONTAINER_NAME already running -- stopping..."
    docker stop $CONTAINER_NAME
    echo "...stopped."
  fi
  echo "postgres/setup: Starting container $CONTAINER_NAME on port local port $PORT..."
  docker run -itd --rm --name $CONTAINER_NAME -e POSTGRES_PASSWORD=password $IMAGE_TAG
  echo "...started."
}

function waitFor() {
  VERSION=$1
  TYPE=$2
  PORT=$3
  CONTAINER_NAME="zgrab_postgres_${VERSION}-${TYPE}"
  echo "postgres/setup: Waiting for postgres process to come up on $CONTAINER_NAME..."
  while ! (docker exec $CONTAINER_NAME ps -Af | grep "postgres: logger process" > /dev/null); do
    echo -n "*"
    sleep 1
  done
  echo "...postgres is up."
}

pushd container
docker images --format {{.Repository}}:{{.Tag}} > images.tmp 

for version in $versions; do
  for type in $types; do
    doSetup $version $type
  done
done

echo "postgres/setup: Waiting for all postgres containers to start up..."

for version in $versions; do
  for type in $types; do
    waitFor $version $type
  done
done

echo "postgres/setup: Containers started."
