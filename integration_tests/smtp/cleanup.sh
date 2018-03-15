#!/usr/bin/env bash

set +e

echo "smtp/cleanup: Tests cleanup for smtp"

CONTAINER_NAME=zgrab_smtp

docker stop $CONTAINER_NAME
