#!/usr/bin/env bash

set +e

echo "telnet/cleanup: Tests cleanup for telnet"

CONTAINER_NAME=zgrab_telnet

docker stop $CONTAINER_NAME
