#!/usr/bin/env bash

set +e

echo "socks5/cleanup: Tests cleanup for socks5"

CONTAINER_NAME=zgrab_socks5

docker stop $CONTAINER_NAME
