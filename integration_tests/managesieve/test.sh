#!/usr/bin/env bash

set -e
MODULE_DIR=$(dirname $0)
ZGRAB_ROOT=$(git rev-parse --show-toplevel)
ZGRAB_OUTPUT=$ZGRAB_ROOT/zgrab-output

mkdir -p $ZGRAB_OUTPUT/managesieve

CONTAINER_NAME=zgrab_managesieve

OUTPUT_FILE=$ZGRAB_OUTPUT/managesieve/managesieve.json

echo "managesieve/test: Tests runner for managesieve"
CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh managesieve > $OUTPUT_FILE
SERVER_IMPLEMENTATION=$(jp -u data.managesieve.result.implementation < $OUTPUT_FILE)
if [[ "$SERVER_IMPLEMENTATION" == "Stalwart"* ]]; then
  echo "managesieve/test: Server implementation looks good: $SERVER_IMPLEMENTATION"
else
  echo "managesieve/test: Server implementation looks wrong: Got $SERVER_IMPLEMENTATION, expected something starting with 'Stalwart'. Full output: [["
  cat $OUTPUT_FILE
  echo "]]"
  exit 1
fi

# Dump the docker logs
echo "managesieve/test: BEGIN docker logs from $CONTAINER_NAME [{("
docker logs --tail all $CONTAINER_NAME
echo ")}] END docker logs from $CONTAINER_NAME"
