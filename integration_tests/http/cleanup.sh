#!/usr/bin/env bash

set +e

echo "http/cleanup: Tests cleanup for http"

CONTAINER_NAME="zgrab_http"

docker stop $CONTAINER_NAME
