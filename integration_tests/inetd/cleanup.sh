#!/usr/bin/env bash

set +e

echo "inetd/cleanup: Tests cleanup for inetd"

CONTAINER_NAME=zgrab_inetd

docker stop $CONTAINER_NAME
