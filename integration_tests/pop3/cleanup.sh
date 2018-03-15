#!/usr/bin/env bash

set +e

echo "pop3/cleanup: Tests cleanup for pop3"

CONTAINER_NAME=zgrab_pop3

docker stop $CONTAINER_NAME
