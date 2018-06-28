#!/usr/bin/env bash

set +e

versions="cups cups-tls"

echo "ipp/cleanup: Tests cleanup for ipp"

for version in $versions; do
    CONTAINER_NAME="zgrab_ipp_$version"

    docker stop $CONTAINER_NAME
done