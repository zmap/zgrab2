#!/usr/bin/env bash

set -e
MODULE_DIR=$(dirname $0)
TEST_ROOT=$MODULE_DIR/..
ZGRAB_ROOT=$MODULE_DIR/../..
ZGRAB_OUTPUT=$ZGRAB_ROOT/zgrab-output

CONTAINER_NAME="zgrab_mssql-2017-linux"

mkdir -p $ZGRAB_OUTPUT/mssql

OUTPUT_FILE="$ZGRAB_OUTPUT/mssql/2017-linux.json"

echo "mssql/test: Tests runner for mssql"
CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh mssql > $OUTPUT_FILE
