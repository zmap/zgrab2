#!/usr/bin/env bash

# Runs the zgrab2_runner docker image (built with docker-runner/build-runner.sh)
# Links the runner image to the targetted container with the hostname alias "target",
# then scans target using the arguments to the script.

if [ -x $CONTAINER_NAME ]; then
  echo "docker-run.sh: Must provide CONTAINER_NAME environment variable"
  exit 1
fi

set -e
docker run --link $CONTAINER_NAME:target -e ZGRAB_TARGET=target zgrab2_runner $@
