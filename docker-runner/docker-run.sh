#!/usr/bin/env bash

# Runs the zgrab2_runner docker image (built with docker-runner/build-runner.sh)
# Links the runner image to the targetted container with the hostname alias "target",
# then scans target using the arguments to the script.

: "${CONTAINER_NAME:?}"

set -e
echo 'target' | docker run --rm -i --link $CONTAINER_NAME:target zgrab2_runner $@
