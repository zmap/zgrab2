#!/usr/bin/env bash

set -e
MODULE_DIR=$(dirname $0)
TEST_ROOT=$MODULE_DIR/..
ZGRAB_ROOT=$MODULE_DIR/../..
ZGRAB_OUTPUT=$ZGRAB_ROOT/zgrab-output

CONTAINER_NAME="zgrab_ftp"

# Run the FTP-specific integration tests:
# 1. Run zgrab2 on the container

mkdir -p $ZGRAB_OUTPUT/ftp

OUTPUT_DIR="$ZGRAB_OUTPUT/ftp"

echo "ftp/test: Testing FTP with --authtls on $CONTAINER_NAME..."
CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh ftp --authtls > $OUTPUT_DIR/authtls.json

echo "ftp/test: Testing FTP on $CONTAINER_NAME..."
CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh ftp > $OUTPUT_DIR/default.json

echo "ftp/test: BEGIN vsftpd logs from $CONTAINER_NAME [{("
docker exec -t $CONTAINER_NAME cat //var/log/vsftpd.log
echo ")}] END vsftpd logs from $CONTAINER_NAME"

echo "ftp/test: BEGIN docker logs from $CONTAINER_NAME [{("
docker logs --tail all $CONTAINER_NAME
echo ")}] END docker logs from $CONTAINER_NAME"
