#!/usr/bin/env bash

set -e

versions="9.3 9.4 9.5 9.6 10.1"
types="ssl nossl"

function doSetup() {
  VERSION=$1
  TYPE=$2
  CONTAINER_NAME="zgrab_postgres_${VERSION}-${TYPE}"
  IMAGE_TAG="zgrab_postgres:${VERSION}-${TYPE}"
  if docker ps --filter "name=$CONTAINER_NAME" | grep -q $CONTAINER_NAME; then
    echo "postgres/setup: Container $CONTAINER_NAME already running -- nothing to do."
    return
  fi
  if grep -q "$IMAGE_TAG" < images.tmp > /dev/null && [ -x $REBUILD ]; then
    echo "postgres/setup: docker image $IMAGE_TAG already exists -- skipping."
  else
    echo "postgres/setup: docker image $IMAGE_TAG does not exist -- creating..."
    ./build.sh $TYPE $VERSION
  fi
  echo "postgres/setup: Starting container $CONTAINER_NAME..."
  docker run -td --rm --name $CONTAINER_NAME -e POSTGRES_PASSWORD=password $IMAGE_TAG
  echo "...started."
}

function waitFor() {
  VERSION=$1
  TYPE=$2
  PORT=$3
  CONTAINER_NAME="zgrab_postgres_${VERSION}-${TYPE}"
  echo "postgres/setup: Waiting for postgres process to come up on $CONTAINER_NAME..."
  if [ "10.1" == "$VERSION" ]; then
    while ! (docker logs --tail all $CONTAINER_NAME | grep -q " listening on IPv4 address"); do
      echo -n "."
      sleep 1
    done
  else
    CNT=0
    while ! (docker exec $CONTAINER_NAME ps -Af | grep -q "postgres: logger process"); do
      echo -n "*" 
      CNT=$((CNT+1))
      if [ $CNT > 20 ]; then
        break
      fi
      sleep 1
    done
    while ! (docker exec $CONTAINER_NAME cat //var/lib/postgresql/data/pg_log/postgres.log | grep -q "STARTED; state"); do
      echo -n "."
      sleep 1
    done
  fi
  sleep 1
  echo "...postgres is up."
}

pushd container
docker images --format {{.Repository}}:{{.Tag}} > images.tmp 

for version in $versions; do
  for type in $types; do
    doSetup $version $type
  done
done

rm -f images.tmp
popd
echo "postgres/setup: Waiting for all postgres containers to start up..."

for version in $versions; do
  for type in $types; do
    waitFor $version $type
  done
done

echo "postgres/setup: Containers started."
