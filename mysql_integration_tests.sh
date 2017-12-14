#!/bin/bash -e

# Run the MySQL-specific integration tests:
# 1. Run zgrab2 on localhost:$MYSQL_PORT
# 2. Check that data.mysql.result.handshake.parsed.server_version matches $MYSQL_VERSION

if [ -z $MYSQL_PORT ] || [ -z $MYSQL_VERSION ]; then
    echo "Must set MYSQL_PORT and MYSQL_VERSION"
    exit 1
fi

mkdir -p $ZGRAB_OUTPUT/mysql

CONTAINER_NAME="testmysql-$MYSQL_VERSION"
OUTPUT_FILE="$ZGRAB_OUTPUT/mysql/$MYSQL_VERSION.json"

echo "Testing MySQL Version $MYSQL_VERSION on port $MYSQL_PORT..."
echo "127.0.0.1" | ./cmd/zgrab2/zgrab2 mysql -p $MYSQL_PORT $* > $OUTPUT_FILE

SERVER_VERSION=$(./jp data.mysql.result.handshake.parsed.server_version < $OUTPUT_FILE)

if [[ "$SERVER_VERSION" =~ "$MYSQL_VERSION\..*" ]]; then
    echo "Server version matches expected version: $SERVER_VERSION =~ $MYSQL_VERSION"
    exit 0
else
    echo "Server versiom mismatch: Got $SERVER_VERSION, expected $MYSQL_VERSION.*"
    exit 1
fi
