#!/usr/bin/env bash

set -e
MODULE_DIR=$(dirname $0)
ZGRAB_ROOT=$(git rev-parse --show-toplevel)
ZGRAB_OUTPUT=$ZGRAB_ROOT/zgrab-output

mkdir -p $ZGRAB_OUTPUT/rdp

function dumpDockerLogs() {
  echo "rdp/test: BEGIN docker logs from $CONTAINER_NAME [{("
  docker logs --tail all $CONTAINER_NAME
  echo ")}] END docker logs from $CONTAINER_NAME"
}

# Test 1: xrdp with TLS (default config)
function testTLS() {
  CONTAINER_NAME=zgrab_rdp
  echo "rdp/test: Testing RDP TLS on $CONTAINER_NAME..."
  CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh rdp > $ZGRAB_OUTPUT/rdp/tls.json
  dumpDockerLogs
}

# Test 2: xrdp with standard RDP security (no TLS)
function testStandard() {
  CONTAINER_NAME=zgrab_rdp_standard
  echo "rdp/test: Testing RDP standard on $CONTAINER_NAME..."
  CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh rdp > $ZGRAB_OUTPUT/rdp/standard.json
  dumpDockerLogs
}

echo "rdp/test: Tests runner for rdp"

testTLS
testStandard

# Validation helpers
function checkFileForField() {
  FILE=$1
  FIELD=$2
  echo "check $FILE for $FIELD"
  RESULT=$(jp data.rdp.result.$FIELD < $FILE)
  if [ "$RESULT" = "null" ]; then
    echo "Did not find $FIELD in $FILE [["
    cat $FILE
    echo "]]"
    exit 1
  fi
}

function checkFileForFieldValue() {
  FILE=$1
  FIELD=$2
  EXPECTED=$3
  echo "check $FILE for $FIELD == $EXPECTED"
  RESULT=$(jp -u data.rdp.result.$FIELD < $FILE)
  if [ "$RESULT" != "$EXPECTED" ]; then
    echo "Expected $FIELD=$EXPECTED, got '$RESULT' in $FILE [["
    cat $FILE
    echo "]]"
    exit 1
  fi
}

function checkFileForLackOfField() {
  FILE=$1
  FIELD=$2
  echo "check $FILE for lack of $FIELD"
  RESULT=$(jp data.rdp.result.$FIELD < $FILE)
  if [ "$RESULT" != "null" ]; then
    echo "Did find $FIELD in $FILE [["
    cat $FILE
    echo "]]"
    exit 1
  fi
}

# TLS variant: should negotiate ssl, have tls log, no ntlm
checkFileForFieldValue $ZGRAB_OUTPUT/rdp/tls.json selected_protocol ssl
checkFileForField $ZGRAB_OUTPUT/rdp/tls.json tls
checkFileForField $ZGRAB_OUTPUT/rdp/tls.json negotiation_flags
checkFileForLackOfField $ZGRAB_OUTPUT/rdp/tls.json ntlm

# Standard variant: should negotiate standard_rdp, no tls, no ntlm
checkFileForFieldValue $ZGRAB_OUTPUT/rdp/standard.json selected_protocol standard_rdp
checkFileForLackOfField $ZGRAB_OUTPUT/rdp/standard.json tls
checkFileForLackOfField $ZGRAB_OUTPUT/rdp/standard.json ntlm

echo "rdp/test: all tests passed"
