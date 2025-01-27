#!/usr/bin/env bash

set +e

echo "mqtt/cleanup: Tests cleanup for mqtt"

CONTAINER_NAME=zgrab_mqtt

docker stop $CONTAINER_NAME
