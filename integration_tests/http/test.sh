#!/usr/bin/env bash

set -e
MODULE_DIR=$(dirname $0)
TEST_ROOT=$MODULE_DIR/..
ZGRAB_ROOT=$MODULE_DIR/../..
ZGRAB_OUTPUT=$ZGRAB_ROOT/zgrab-output

mkdir -p $ZGRAB_OUTPUT/http

OUTPUT_FILE=http.json

CONTAINER_NAME=zgrab_http

echo "http/test: Tests runner for http"
CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh http > $OUTPUT_FILE

echo "http/test: BEGIN docker logs from $CONTAINER_NAME [{("
docker logs --tail all $CONTAINER_NAME
echo ")}] END docker logs from $CONTAINER_NAME"

echo "http/test: BEGIN https logs from $CONTAINER_NAME [{("
docker exec -it $CONTAINER_NAME cat //var/log/lighttpd/https.log
echo ")}] END docker logs from $CONTAINER_NAME"

echo "http/test: BEGIN http logs from $CONTAINER_NAME [{("
docker exec -it $CONTAINER_NAME cat //var/log/lighttpd/http.log
echo ")}] END docker logs from $CONTAINER_NAME"
