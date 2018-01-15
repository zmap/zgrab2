#!/usr/bin/env bash

set +e

CONTAINER_NAME="zgrab_ssh"

docker stop $CONTAINER_NAME
