#!/usr/bin/env bash

set -e
MODULE_DIR=$(dirname $0)
ZGRAB_ROOT=$(git rev-parse --show-toplevel)
ZGRAB_OUTPUT=$ZGRAB_ROOT/zgrab-output

mkdir -p $ZGRAB_OUTPUT/#{MODULE_NAME}

CONTAINER_NAME=zgrab_#{MODULE_NAME}

OUTPUT_FILE=$ZGRAB_OUTPUT/#{MODULE_NAME}/#{MODULE_NAME}.json

echo "#{MODULE_NAME}/test: Tests runner for #{MODULE_NAME}"
# TODO FIXME: Add any necessary flags or additional tests
CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh #{MODULE_NAME} > $OUTPUT_FILE

# Dump the docker logs
echo "#{MODULE_NAME}/test: BEGIN docker logs from $CONTAINER_NAME [{("
docker logs --tail all $CONTAINER_NAME
echo ")}] END docker logs from $CONTAINER_NAME"

# TODO: If there are any other relevant log files, dump those to stdout here.
