#!/usr/bin/env bash

# This will build our custom postgres docker image for the requested type (ssl/nossl) and postgres version.
# 

set -e

TYPE=$1
VERSION=$2

if [ "$#" -ne 2 ] || ! ( [ "$TYPE" = "ssl" ] || [ "$TYPE" = "nossl" ] ); then
  echo "integration_tests/postgres/container/build.sh: Build a zgrab_postgres docker image"
  echo ""
  echo "Usage:"
  echo ""
  echo "  $0 [type] [version]"
  echo ""
  echo "...where [type] is \"ssl\" or \"nossl\", and [version] is the postgres server version."
  echo ""
  echo "On success, creates an image tagged zgrab_postgres:[version]-[type]".
  echo ""
  exit 1
fi

# If there is a Dockerfile specifically for this version, use that
if [ -f Dockerfile.$VERSION ]; then
  cp Dockerfile.$VERSION Dockerfile
else
  # TODO: There must be a better way to do this.
  # The reason for the sed is, you cannot use build-args in the FROM directive.
  # And, it doesn't seem that you can forward the version tag in the docker run command to the 'parent' image.
  # So, it seems we're stuck creating a bunch of images whose only difference is the version tag in the FROM statement at build time.
  # Or, using the base images, which don't have SSL or logging enabled.

  sed "s!#{POSTGRES_VERSION}!$VERSION!g" < Dockerfile.template > Dockerfile
fi

docker build --build-arg IMAGE_TYPE=$TYPE -t zgrab_postgres:$VERSION-$TYPE .
rm Dockerfile
