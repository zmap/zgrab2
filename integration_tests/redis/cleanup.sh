#!/usr/bin/env bash

set +e

echo "redis/cleanup: Tests cleanup for redis"

configs="default password renamed"

for cfg in $configs; do
    CONTAINER_NAME="zgrab_redis_${cfg}"
    docker stop $CONTAINER_NAME
done
