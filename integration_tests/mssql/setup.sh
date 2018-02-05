#!/usr/bin/env bash

echo "mssql/setup: Tests setup for mssql"

CONTAINER_IMAGE="microsoft/mssql-server-linux"
CONTAINER_VERSION="2017-CU3"
CONTAINER_NAME="zgrab_mssql-2017-linux"

# Supported MSSQL_PRODUCT_ID values are Developer, Express, Standard, Enterprise, EnterpriseCore
MSSQL_PRODUCT_ID="Enterprise"

if docker ps --filter "name=$CONTAINER_NAME" | grep $CONTAINER_NAME; then
    echo "mssql/setup: Container $CONTAINER_NAME already running -- nothing more to do."
    exit 0
fi

docker run -td --rm -e "MSSQL_PID=$MSSQL_PRODUCT_ID" -e "ACCEPT_EULA=Y" -e "SA_PASSWORD=$(openssl rand -base64 12)" --name $CONTAINER_NAME $CONTAINER_IMAGE:$CONTAINER_VERSION

echo -n "mssql/setup: Waiting on $CONTAINER_NAME..."

while ! docker logs $CONTAINER_NAME --tail all | grep -q "Server is listening on"; do
    echo -n "."
    sleep 1
done

sleep 1

echo "...done."
