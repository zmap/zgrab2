#!/usr/bin/env bash

set +e

echo "ipp/cleanup: Tests cleanup for ipp"

CONTAINER_NAME=zgrab_ipp

docker stop $CONTAINER_NAME
