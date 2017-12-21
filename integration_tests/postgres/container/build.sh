#!/usr/bin/env bash

set -e

TYPE=$1
VERSION=$2

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 [type] [version]"
  exit 1
fi

if [ -f Dockerfile.$VERSION ]; then
  cp Dockerfile.$VERSION Dockerfile
else
  # TODO: There must be a better way to do this.
  # The reason for the sed is, you cannot use build-args in the FROM directive.
  # And, it doesn't seem that you can forward the version tag in the docker run command to the 'parent' image.
  # So, it seems we're stuck creating a bunch of images whose only difference is the version tag in the FROM statement at build time.

  sed "s!#{POSTGRES_VERSION}!$VERSION!g" < Dockerfile.template > Dockerfile
fi

docker build --build-arg IMAGE_TYPE=$TYPE -t zgrab_postgres:$VERSION-$TYPE .
rm Dockerfile
