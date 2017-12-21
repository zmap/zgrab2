#!/usr/bin/env bash

set -e

pushd container
versions="9.3 9.4 9.5 9.6 10.1"
types="ssl nossl"
docker images --format {{.Repository}}:{{.Tag}} > images.tmp 
for version in $versions; do
  for type in $types; do
    IMAGE_TAG="zgrab_postgres:$version-$type"
    if grep "$IMAGE_TAG" < images.tmp > /dev/null && [ -x $REBUILD ]; then
      echo "docker image $IMAGE_TAG already exists -- skipping."
    else
      echo "docker image $IMAGE_TAG does not exist -- creating..."
      ./build.sh $type $version
    fi
  done
done
popd
echo "Starting containers..."
docker run -itd -p 35432:5432 --rm --name zgrab_postgres_9.3-ssl -e POSTGRES_PASSWORD=password zgrab_postgres:9.3-ssl
docker run -itd -p 35433:5432 --rm --name zgrab_postgres_9.4-ssl -e POSTGRES_PASSWORD=password zgrab_postgres:9.4-ssl
docker run -itd -p 35434:5432 --rm --name zgrab_postgres_9.5-ssl -e POSTGRES_PASSWORD=password zgrab_postgres:9.5-ssl
docker run -itd -p 35435:5432 --rm --name zgrab_postgres_9.6-ssl -e POSTGRES_PASSWORD=password zgrab_postgres:9.6-ssl
docker run -itd -p 35436:5432 --rm --name zgrab_postgres_10.1-ssl -e POSTGRES_PASSWORD=password zgrab_postgres:10.1-ssl

docker run -itd -p 45432:5432 --rm --name zgrab_postgres_9.3-nossl -e POSTGRES_PASSWORD=password zgrab_postgres:9.3-nossl
docker run -itd -p 45433:5432 --rm --name zgrab_postgres_9.4-nossl -e POSTGRES_PASSWORD=password zgrab_postgres:9.4-nossl
docker run -itd -p 45434:5432 --rm --name zgrab_postgres_9.5-nossl -e POSTGRES_PASSWORD=password zgrab_postgres:9.5-nossl
docker run -itd -p 45435:5432 --rm --name zgrab_postgres_9.6-nossl -e POSTGRES_PASSWORD=password zgrab_postgres:9.6-nossl
docker run -itd -p 45436:5432 --rm --name zgrab_postgres_10.1-nossl -e POSTGRES_PASSWORD=password zgrab_postgres:10.1-nossl

echo "Containers started."
