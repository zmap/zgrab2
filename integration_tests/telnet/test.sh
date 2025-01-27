#!/usr/bin/env bash

set -e
MODULE_DIR=$(dirname $0)
ZGRAB_ROOT=$(git rev-parse --show-toplevel)
ZGRAB_OUTPUT=$ZGRAB_ROOT/zgrab-output

mkdir -p $ZGRAB_OUTPUT/telnet

CONTAINER_NAME=zgrab_telnet

OUTPUT_FILE=$ZGRAB_OUTPUT/telnet/telnet.json

echo "telnet/test: Tests runner for telnet"
CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh telnet > $OUTPUT_FILE

# Dump the docker logs
echo "telnet/test: BEGIN docker logs from $CONTAINER_NAME [{("
docker logs --tail all $CONTAINER_NAME
echo ")}] END docker logs from $CONTAINER_NAME"

# TODO: If there are any other relevant log files, dump those to stdout here.
