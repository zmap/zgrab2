#!/usr/bin/env bash

set +e

CONTAINER_NAME="zgrab_mssql-2017-linux"

echo "mssql/cleanup: Tests cleanup for mssql"

docker stop $CONTAINER_NAME
