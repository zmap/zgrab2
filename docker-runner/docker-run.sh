#!/usr/bin/env bash

# Runs the zgrab2_runner docker image (built with docker-runner/build-runner.sh)
# Links the runner image to the targeted container with the hostname alias "target"
# (or $target_name if set), then scans it using the arguments to the script.

: "${CONTAINER_NAME:?}"

set -e
TARGET_NAME="${TARGET_NAME:-target}"

echo "$TARGET_NAME" | docker run --rm -i --network container:"$CONTAINER_NAME" zgrab2_runner --blocklist-file="" $@
