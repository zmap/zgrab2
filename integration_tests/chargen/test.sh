#!/usr/bin/env bash

set -e
MODULE_DIR=$(dirname $0)
TEST_ROOT=$MODULE_DIR/..
ZGRAB_ROOT=$MODULE_DIR/../..
ZGRAB_OUTPUT=$ZGRAB_ROOT/zgrab-output

mkdir -p $ZGRAB_OUTPUT/chargen

# OUTPUT_FILE=[TODO].json

echo "chargen/test: Tests runner for chargen"
# CONTAINER_NAME=[TODO] $ZGRAB_ROOT/docker-runner/docker-run.sh chargen > $OUTPUT_FILE

