#!/usr/bin/env bash

set -e
MODULE_DIR=$(dirname $0)
TEST_ROOT=$MODULE_DIR/..
ZGRAB_ROOT=$MODULE_DIR/../..
ZGRAB_OUTPUT=$ZGRAB_ROOT/zgrab-output

CONTAINER_NAME=zgrab_ntp

mkdir -p $ZGRAB_OUTPUT/ntp

OUTPUT_FILE=$ZGRAB_OUTPUT/ntp/ntp.json

echo "ntp/test: Tests runner for ntp"
CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh ntp > $OUTPUT_FILE
