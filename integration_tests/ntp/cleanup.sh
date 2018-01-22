#!/usr/bin/env bash

set +e

echo "ntp/cleanup: Tests cleanup for ntp"

CONTAINER_NAME="zgrab_ntp"

docker stop $CONTAINER_NAME
