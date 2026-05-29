#!/usr/bin/env bash

set -e
MODULE_DIR=$(dirname $0)
ZGRAB_ROOT=$(git rev-parse --show-toplevel)
ZGRAB_OUTPUT=$ZGRAB_ROOT/zgrab-output

mkdir -p $ZGRAB_OUTPUT/checkpoint

CONTAINER_NAME=zgrab_checkpoint

OUTPUT_FILE=$ZGRAB_OUTPUT/checkpoint/checkpoint.json

echo "checkpoint/test: Running checkpoint scan against $CONTAINER_NAME"
CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh checkpoint > $OUTPUT_FILE

echo "checkpoint/test: BEGIN docker logs from $CONTAINER_NAME [{("
docker logs --tail all $CONTAINER_NAME
echo ")}] END docker logs from $CONTAINER_NAME"
