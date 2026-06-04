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

# Validate output against the defaults baked into server.py.
EXPECTED_FIREWALL="fw1.example.com"
EXPECTED_SMARTCENTER="smartcenter.example.com"
EXPECTED_OBJECT_SUFFIX="oo2u8w"
EXPECTED_CIPHER_COUNT="12"

STATUS=$(jq -r '.data.checkpoint.status' < "$OUTPUT_FILE")
if [ "$STATUS" != "success" ]; then
    echo "checkpoint/test: FAIL - expected status 'success', got '$STATUS'"
    exit 1
fi

FIREWALL=$(jq -r '.data.checkpoint.result.firewall_host' < "$OUTPUT_FILE")
if [ "$FIREWALL" != "$EXPECTED_FIREWALL" ]; then
    echo "checkpoint/test: FAIL - firewall_host: expected '$EXPECTED_FIREWALL', got '$FIREWALL'"
    exit 1
fi

SMARTCENTER=$(jq -r '.data.checkpoint.result.smart_center_host' < "$OUTPUT_FILE")
if [ "$SMARTCENTER" != "$EXPECTED_SMARTCENTER" ]; then
    echo "checkpoint/test: FAIL - smart_center_host: expected '$EXPECTED_SMARTCENTER', got '$SMARTCENTER'"
    exit 1
fi

OBJECT_SUFFIX=$(jq -r '.data.checkpoint.result.object_suffix' < "$OUTPUT_FILE")
if [ "$OBJECT_SUFFIX" != "$EXPECTED_OBJECT_SUFFIX" ]; then
    echo "checkpoint/test: FAIL - object_suffix: expected '$EXPECTED_OBJECT_SUFFIX', got '$OBJECT_SUFFIX'"
    exit 1
fi

CIPHER_COUNT=$(jq '.data.checkpoint.result.supported_ciphers | length' < "$OUTPUT_FILE")
if [ "$CIPHER_COUNT" != "$EXPECTED_CIPHER_COUNT" ]; then
    echo "checkpoint/test: FAIL - supported_ciphers count: expected $EXPECTED_CIPHER_COUNT, got $CIPHER_COUNT"
    exit 1
fi

echo "checkpoint/test: PASS"
