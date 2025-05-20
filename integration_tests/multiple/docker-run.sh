#!/usr/bin/env bash

# Runs the zgrab2_runner docker image (built with docker-runner/build-runner.sh)

: "${DIR:?}"

set -e
docker run --rm -i -v $DIR:/multiple zgrab2_runner $@
