#!/bin/bash -e

# These are all of the versions supported by https://hub.docker.com/_/mysql/
VERSIONS="5.5 5.6 5.7 8.0"

# Unfortunately, the 5.5/5.6 containers do not have TLS support built in, so for now we are constrained to checking the version string

for version in $VERSIONS; do
    ./test_mysql_version.sh "$version"
done
