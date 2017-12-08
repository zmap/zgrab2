#!/bin/bash
if [ "$#" -lt 1 ]; then
  echo "Usage:"
  echo ""
  echo "    $0 [version]"
  echo ""
  echo "[version] should be one of the supported tags listed at https://hub.docker.com/_/mysql/"
  echo ""
  echo "Example:"
  echo ""
  echo "    $0 5.5"
  echo ""
  exit 1
fi

SQL_VERSION="$1"
CONTAINER_NAME="testmysql-$SQL_VERSION"
OUTPUT_FILE="out-$SQL_VERSION.json"

shift

echo "Starting the mysql $SQL_VERSION container (forwarding localhost:3306 -> container:3306)..."
set -x
if ! docker run -itd -p 3306:3306 --rm --name $CONTAINER_NAME -e MYSQL_ROOT_PASSWORD=rootPassword mysql:$SQL_VERSION; then
  echo "Error running mysql:$SQL_VERSION docker instance: $?"
  exit 1
fi
set +x

function cleanup {
  echo "Stopping $CONTAINER_NAME..."
  docker stop $CONTAINER_NAME
  echo "Stopped."
}

trap cleanup EXIT

set +e

pushd cmd/zgrab2
go build -o ../../zgrab2
popd

echo "Waiting for port 3306 to come up..."
while ! (netstat -n -a | grep 3306 | grep LISTENING > /dev/null); do sleep 1; done
# 5s seems to work more than half the time on my laptop, 10s seems to work all the time
sleep 10

set -x
echo "127.0.0.1" | ./zgrab2 mysql $* > $OUTPUT_FILE
set +x
SERVER_VERSION=$(jp data.mysql.result.handshake.parsed.server_version < $OUTPUT_FILE)

if [[ "$SERVER_VERSION" =~ "$SQL_VERSION\..*" ]]; then
  echo "Server version matches expected version: $SERVER_VERSION =~ $SQL_VERSION"
else
  echo "Server versiom mismatch: Got $SERVER_VERSION, expected $SQL_VERSION.*"
  exit 1
fi
