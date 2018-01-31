#!/usr/bin/env bash

set +e

echo "#{MODULE_NAME}/cleanup: Tests cleanup for #{MODULE_NAME}"

CONTAINER_NAME=zgrab_#{MODULE_NAME}

docker stop $CONTAINER_NAME
