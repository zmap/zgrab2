#!/bin/sh -e
SQL_VERSION="$1"
PORT="$2"
CONTAINER_NAME="testmysql-$SQL_VERSION"
OUTPUT_FILE="out-$SQL_VERSION.json"
ZSCHEMA_PATH=zschema

shift
shift

echo "Testing MySQL Version $SQL_VERSION on port $PORT..."
echo "127.0.0.1" | ./cmd/zgrab2/zgrab2 mysql -p $PORT $* > $OUTPUT_FILE

cat $OUTPUT_FILE

if [ -d zschema ]; then
  PYTHONPATH=$PYTHONPATH:$ZSCHEMA_PATH python -m zschema validate schemas/__init__.py:zgrab2 $OUTPUT_FILE
else
  echo "Skipping schema validation: clone zschema into $ZSCHEMA_PATH to enable"
fi

SERVER_VERSION=$(jp data.mysql.result.handshake.parsed.server_version < $OUTPUT_FILE)

if [[ "$SERVER_VERSION" =~ "$SQL_VERSION\..*" ]]; then
  echo "Server version matches expected version: $SERVER_VERSION =~ $SQL_VERSION"
  exit 0
else
  echo "Server versiom mismatch: Got $SERVER_VERSION, expected $SQL_VERSION.*"
  exit 1
fi
