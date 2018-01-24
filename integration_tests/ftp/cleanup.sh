#!/usr/bin/env bash

set +e

CONTAINER_NAME="zgrab_ftp"

docker stop $CONTAINER_NAME
