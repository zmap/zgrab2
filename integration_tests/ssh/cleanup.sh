#!/bin/bash +e

CONTAINER_NAME="sshtest"

echo "BEGIN DOCKER LOGS FROM $CONTAINER_NAME [{("
docker logs --tail all $CONTAINER_NAME
echo ")}] END DOCKER LOGS FROM $CONTAINER_NAME"

docker stop $CONTAINER_NAME
