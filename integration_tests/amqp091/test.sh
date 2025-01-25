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
  
  SUFFIX=""
  AUTH_ARGS=""
  if [[ -n "$2" ]]; then
    AUTH_ARGS=$2
    SUFFIX="-auth"
  fi
  CONTAINER_NAME="zgrab_amqp091-${MQ_VERSION}"
  OUTPUT_FILE="$ZGRAB_OUTPUT/amqp091/${MQ_VERSION}${SUFFIX}.json"
  echo "amqp091/test: Testing RabbitMQ Version ${MQ_VERSION}${SUFFIX}..."
  CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh amqp091 $AUTH_ARGS --timeout 10s >$OUTPUT_FILE
  SERVER_VERSION=$(jp -u data.amqp091.result.server_properties.version <$OUTPUT_FILE)
  if [[ "$SERVER_VERSION" == "$MQ_VERSION" ]]; then
    echo "amqp091/test: Server version matches expected version: $SERVER_VERSION == $MQ_VERSION"
  else
    echo "amqp091/test: Server version mismatch: Got $SERVER_VERSION, expected $MQ_VERSION. Full output: [["
    cat $OUTPUT_FILE
    echo "]]"
    status=1
  fi

  if [[ -n "$AUTH_ARGS" ]]; then
    AUTH_SUCCESS=$(jp -u data.amqp091.result.auth_success <$OUTPUT_FILE)
    if [[ "$AUTH_SUCCESS" == "true" ]]; then
      echo "amqp091/test: Auth test successful"
    else
      echo "amqp091/test: Auth test failed"
      status=1
    fi
  fi

  echo "amqp091/test: BEGIN docker+amqp091 logs from $CONTAINER_NAME [{("
  docker logs --tail all $CONTAINER_NAME
  echo ")}] END docker+amqp091 logs from $CONTAINER_NAME"
}

mkdir -p $ZGRAB_OUTPUT/amqp091

for version in $VERSIONS; do
  doTest $version
  doTest $version "--auth-user guest --auth-pass guest"
done

exit $status
