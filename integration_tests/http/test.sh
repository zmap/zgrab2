#!/usr/bin/env bash

set -e
MODULE_DIR=$(dirname $0)
TEST_ROOT=$MODULE_DIR/..
ZGRAB_ROOT=$MODULE_DIR/../..
ZGRAB_OUTPUT=$ZGRAB_ROOT/zgrab-output

OUTPUT_ROOT=$ZGRAB_OUTPUT/http

mkdir -p $OUTPUT_ROOT

CONTAINER_NAME=zgrab_http

echo "http/test: Run http test in default port (should be 80)"
CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh http > $OUTPUT_ROOT/http.json

echo "http/test: Run https test on port 443"
CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh http --port 443 --use-https > $OUTPUT_ROOT/https.json

# TODO: Tests with local / remote redirection

# TODO: Test various types of content (binary, JSON, ...)

# TODO: Test with client cert required

echo "http/test: BEGIN docker logs from $CONTAINER_NAME [{("
docker logs --tail all $CONTAINER_NAME
echo ")}] END docker logs from $CONTAINER_NAME"

echo "http/test: BEGIN https logs from $CONTAINER_NAME [{("
docker exec -it $CONTAINER_NAME cat //var/log/lighttpd/error.log
echo ")}] END docker logs from $CONTAINER_NAME"
