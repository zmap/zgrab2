#!/usr/bin/env bash

set +e

CONTAINER_NAME="zgrab_mssql-2022-linux"

echo "mssql/cleanup: Tests cleanup for mssql"

docker stop $CONTAINER_NAME
