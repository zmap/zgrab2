#!/usr/bin/env bash
set -e

VERSIONS="3.12.14 3.13.2"

# Run the AMQP-specific integration tests:
# 1. Run zgrab2 on the container
# 2. Check that data.amqp091.result.server_properties.version matches $MQ_VERSION

ZGRAB_ROOT=$(git rev-parse --show-toplevel)
ZGRAB_OUTPUT=$ZGRAB_ROOT/zgrab-output

status=0

function doTest() {
  MQ_VERSION=$1
  CONTAINER_NAME="zgrab_amqp091-$MQ_VERSION"
  OUTPUT_FILE="$ZGRAB_OUTPUT/amqp091/$MQ_VERSION.json"
  echo "amqp091/test: Testing MySQL Version $MQ_VERSION..."
  CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh amqp091 --timeout 10s >$OUTPUT_FILE
  SERVER_VERSION=$(jp -u data.amqp091.result.server_properties.version <$OUTPUT_FILE)
  if [[ "$SERVER_VERSION" == "$MQ_VERSION."* ]]; then
    echo "amqp091/test: Server version matches expected version: $SERVER_VERSION == $MQ_VERSION.*"
  else
    echo "amqp091/test: Server version mismatch: Got $SERVER_VERSION, expected $MQ_VERSION.*. Full output: [["
    cat $OUTPUT_FILE
    echo "]]"
    status=1
  fi
  echo "amqp091/test: BEGIN docker+amqp091 logs from $CONTAINER_NAME [{("
  docker logs --tail all $CONTAINER_NAME
  echo ")}] END docker+amqp091 logs from $CONTAINER_NAME"
}

mkdir -p $ZGRAB_OUTPUT/amqp091

for version in $VERSIONS; do
  doTest $version
done

exit $status
