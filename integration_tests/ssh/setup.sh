#!/bin/bash -e

SSH_PORT=33022
CONTAINER_NAME=sshtest

# TODO FIXME: use container with sshd already running; this is definitely not the write way to do this, but it works (slowly)

docker run --rm --name $CONTAINER_NAME -itd -p $SSH_PORT:22 ubuntu:16.04

docker exec $CONTAINER_NAME apt-get update
docker exec $CONTAINER_NAME apt-get install -y openssh-server
docker exec $CONTAINER_NAME service ssh start
