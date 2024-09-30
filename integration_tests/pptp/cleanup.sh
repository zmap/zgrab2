#!/usr/bin/env bash

set +e

echo "pptp/cleanup: Tests cleanup for pptp"

CONTAINER_NAME=zgrab_pptp

docker stop $CONTAINER_NAME
