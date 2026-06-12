#!/usr/bin/env bash

set -e
MODULE_DIR=$(dirname $0)
ZGRAB_ROOT=$(git rev-parse --show-toplevel)
ZGRAB_OUTPUT=$ZGRAB_ROOT/zgrab-output

mkdir -p $ZGRAB_OUTPUT/telnet

OUTPUT_ROOT="$ZGRAB_OUTPUT/telnet"

function dumpDockerLogs() {
  echo "telnet/test: BEGIN docker logs from $CONTAINER_NAME [{("
  docker logs --tail all $CONTAINER_NAME
  echo ")}] END docker logs from $CONTAINER_NAME"
}

echo "telnet/test: Tests runner for telnet"

# Plain telnet test
CONTAINER_NAME=zgrab_telnet
CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh telnet > $OUTPUT_ROOT/telnet.json
dumpDockerLogs

# TLS telnet test (port 992 is the standard telnets port)
CONTAINER_NAME=zgrab_telnet_tls
CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh telnet --tls -p 992 > $OUTPUT_ROOT/telnet_tls.json
dumpDockerLogs

# TLS downgrade tests
# Connecting with --tls --allow-tls-downgrade to the TLS port should succeed with TLS
CONTAINER_NAME=zgrab_telnet_tls
CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh telnet --tls --allow-tls-downgrade -p 992 > $OUTPUT_ROOT/tls_downgrade_tls_port.json
dumpDockerLogs

# Connecting with --tls --allow-tls-downgrade to the plain port should fall back to plaintext
CONTAINER_NAME=zgrab_telnet_tls
CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh telnet --tls --allow-tls-downgrade -p 23 > $OUTPUT_ROOT/tls_downgrade_plain_port.json
dumpDockerLogs
