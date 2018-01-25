#!/usr/bin/env bash

set -e
MODULE_DIR=$(dirname $0)
TEST_ROOT=$MODULE_DIR/..
ZGRAB_ROOT=$MODULE_DIR/../..
ZGRAB_OUTPUT=$ZGRAB_ROOT/zgrab-output

CONTAINER_NAME=zgrab_inetd

services="chargen echo time daytime"

echo "inetd/test: Tests runner for inetd"

for service in $services; do
    echo "inetd/test: Testing $service"
    mkdir -p $ZGRAB_OUTPUT/$service
    CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh $service --timeout 5 > $ZGRAB_OUTPUT/$service/tcp.json
    CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh $service --udp --timeout 5 > $ZGRAB_OUTPUT/$service/udp.json
done
