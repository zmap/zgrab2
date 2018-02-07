#!/usr/bin/env bash

set +e

echo "ntp/cleanup: Tests cleanup for ntp"

versions="openntp 4.2.6"

for version in $versions; do
    CONTAINER_NAME="zgrab_ntp_$version"
    echo "ntp/cleanup: Stopping container $CONTAINER_NAME..."
    docker stop $CONTAINER_NAME
done
