#!/usr/bin/env bash

echo "mssql/setup: Tests setup for mssql"

CONTAINER_IMAGE="microsoft/mssql-server-linux"
CONTAINER_VERSION="2017-CU3"
CONTAINER_NAME="zgrab_mssql-2017-linux"

docker run --rm -e "ACCEPT_EULA=Y" -e "SA_PASSWORD=$(openssl rand -base64 12)" --name $CONTAINER_NAME -d $CONTAINER_IMAGE:$CONTAINER_VERSION
