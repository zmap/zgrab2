#!/usr/bin/env bash
set -e

versions="5.5 5.6 5.7 8.0"

# Run the MySQL-specific integration tests:
# 1. Run zgrab2 on the container
# 2. Check that data.mysql.result.handshake.parsed.server_version matches $MYSQL_VERSION

MODULE_DIR=$(dirname $0)
TEST_ROOT=$MODULE_DIR/..
ZGRAB_ROOT=$(git rev-parse --show-toplevel)
ZGRAB_OUTPUT=$ZGRAB_ROOT/zgrab-output

status=0

function doTest() {
  MYSQL_VERSION=$1
  CONTAINER_NAME="zgrab_mysql-$MYSQL_VERSION"
  OUTPUT_FILE="$ZGRAB_OUTPUT/mysql/$MYSQL_VERSION.json"
  echo "mysql/test: Testing MySQL Version $MYSQL_VERSION..."
  CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh mysql --timeout 10s > $OUTPUT_FILE
  SERVER_VERSION=$(jp -u data.mysql.result.server_version < $OUTPUT_FILE)
  if [[ "$SERVER_VERSION" == "$MYSQL_VERSION."* ]]; then
    echo "mysql/test: Server version matches expected version: $SERVER_VERSION == $MYSQL_VERSION.*"
  else
    echo "mysql/test: Server version mismatch: Got $SERVER_VERSION, expected $MYSQL_VERSION.*. Full output: [["
    cat $OUTPUT_FILE
    echo "]]"
    status=1
  fi
  echo "mysql/test: BEGIN docker+mysql logs from $CONTAINER_NAME [{("
  docker logs --tail all $CONTAINER_NAME
  echo ")}] END docker+mysql logs from $CONTAINER_NAME"
}

mkdir -p $ZGRAB_OUTPUT/mysql

for version in $versions; do
  doTest $version
done

exit $status
