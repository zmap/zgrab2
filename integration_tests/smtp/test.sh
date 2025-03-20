#!/usr/bin/env bash

set -e
MODULE_DIR=$(dirname $0)
ZGRAB_ROOT=$(git rev-parse --show-toplevel)
ZGRAB_OUTPUT=$ZGRAB_ROOT/zgrab-output

mkdir -p $ZGRAB_OUTPUT/smtp

CONTAINER_NAME=zgrab_smtp

OUTPUT_ROOT="$ZGRAB_OUTPUT/smtp"
versions="helo ehlo-no-starttls ehlo-starttls smtps"

function testHelo() {
  CONTAINER_NAME=zgrab_smtp_helo
  CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh smtp > $ZGRAB_OUTPUT/smtp/helo.json
  CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh smtp --send-help > $ZGRAB_OUTPUT/smtp/helo_send_help.json
  CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh smtp --send-quit > $ZGRAB_OUTPUT/smtp/helo_send_quit.json
}

function testEHLO() {
  CONTAINER_NAME=zgrab_smtp_ehlo_starttls
  CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh smtp > $ZGRAB_OUTPUT/smtp/ehlo_starttls.json
  CONTAINER_NAME=zgrab_smtp_ehlo_no_starttls
  CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh smtp > $ZGRAB_OUTPUT/smtp/ehlo_no_starttls.json
}

function testSMTPS() {
  CONTAINER_NAME=zgrab_smtp_smtps
  CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh smtp --smtps > $ZGRAB_OUTPUT/smtp/smtps.json
}
echo "smtp/test: Tests runner for smtp"

testHelo
testEHLO
testSMTPS

#FIELDS="help quit helo ehlo"
#status=0
#for field in $FIELDS; do
#    for file in $(find $OUTPUT_ROOT -iname "*$field*.json"); do
#        echo "check $file for $field"
#        RESULT=$(jp data.smtp.result.$field < $file)
#        if [ "$RESULT" = "null" ]; then
#            echo "Did not find $field in $file [["
#            cat $file
#            echo "]]"
#            status=1
#        fi
#    done
#done

## Dump the docker logs
#echo "smtp/test: BEGIN docker logs from $CONTAINER_NAME [{("
#docker logs --tail all $CONTAINER_NAME
#echo ")}] END docker logs from $CONTAINER_NAME"
#
exit $status
