#!/usr/bin/env bash

set -e
MODULE_DIR=$(dirname $0)
TEST_ROOT=$MODULE_DIR/..
ZGRAB_ROOT=$(git rev-parse --show-toplevel)
ZGRAB_OUTPUT=$ZGRAB_ROOT/zgrab-output

CONTAINER_NAME="zgrab_ssh"

# Run the SSH-specific integration tests:
# 1. Run zgrab2 on the container

mkdir -p $ZGRAB_OUTPUT/ssh

OUTPUT_FILE="$ZGRAB_OUTPUT/ssh/ssh.json"

echo "ssh/test: Testing SSH Version on $CONTAINER_NAME..."
CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh ssh > $OUTPUT_FILE

echo "ssh/test: BEGIN docker logs from $CONTAINER_NAME [{("
docker logs --tail all $CONTAINER_NAME
echo ")}] END docker logs from $CONTAINER_NAME"
