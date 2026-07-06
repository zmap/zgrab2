#!/usr/bin/env bash

set -e
MODULE_DIR=$(dirname $0)
ZGRAB_ROOT=$(git rev-parse --show-toplevel)
ZGRAB_OUTPUT=$ZGRAB_ROOT/zgrab-output

mkdir -p $ZGRAB_OUTPUT/drda

CONTAINER_NAME=zgrab_drda

OUTPUT_FILE=$ZGRAB_OUTPUT/drda/drda.json

echo "drda/test: Running drda scan against $CONTAINER_NAME"
CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh drda --port 50000 > $OUTPUT_FILE

echo "drda/test: BEGIN docker logs from $CONTAINER_NAME [{("
docker logs --tail all $CONTAINER_NAME
echo ")}] END docker logs from $CONTAINER_NAME"

# Validate output against the deterministic values baked into server.py.
EXPECTED_SERVER_CLASS="QDB2/NT64"
EXPECTED_INSTANCE_NAME="DB2"
EXPECTED_RELEASE_LEVEL="SQL11013"
EXPECTED_VERSION="11.01.3"

STATUS=$(jq -r '.data.drda.status' < "$OUTPUT_FILE")
if [ "$STATUS" != "success" ]; then
    echo "drda/test: FAIL - expected status 'success', got '$STATUS'"
    exit 1
fi

SERVER_CLASS=$(jq -r '.data.drda.result.server_class' < "$OUTPUT_FILE")
if [ "$SERVER_CLASS" != "$EXPECTED_SERVER_CLASS" ]; then
    echo "drda/test: FAIL - server_class: expected '$EXPECTED_SERVER_CLASS', got '$SERVER_CLASS'"
    exit 1
fi

INSTANCE_NAME=$(jq -r '.data.drda.result.instance_name' < "$OUTPUT_FILE")
if [ "$INSTANCE_NAME" != "$EXPECTED_INSTANCE_NAME" ]; then
    echo "drda/test: FAIL - instance_name: expected '$EXPECTED_INSTANCE_NAME', got '$INSTANCE_NAME'"
    exit 1
fi

RELEASE_LEVEL=$(jq -r '.data.drda.result.release_level' < "$OUTPUT_FILE")
if [ "$RELEASE_LEVEL" != "$EXPECTED_RELEASE_LEVEL" ]; then
    echo "drda/test: FAIL - release_level: expected '$EXPECTED_RELEASE_LEVEL', got '$RELEASE_LEVEL'"
    exit 1
fi

VERSION=$(jq -r '.data.drda.result.version' < "$OUTPUT_FILE")
if [ "$VERSION" != "$EXPECTED_VERSION" ]; then
    echo "drda/test: FAIL - version: expected '$EXPECTED_VERSION', got '$VERSION'"
    exit 1
fi

echo "drda/test: PASS"
