#!/usr/bin/env bash

set +e

echo "redis/cleanup: Tests cleanup for redis"

CONTAINER_NAME=zgrab_redis

docker stop $CONTAINER_NAME
