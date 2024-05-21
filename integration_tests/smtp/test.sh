#!/usr/bin/env bash

set -e
MODULE_DIR=$(dirname $0)
ZGRAB_ROOT=$(git rev-parse --show-toplevel)
ZGRAB_OUTPUT=$ZGRAB_ROOT/zgrab-output

mkdir -p $ZGRAB_OUTPUT/smtp

CONTAINER_NAME=zgrab_smtp

OUTPUT_ROOT="$ZGRAB_OUTPUT/smtp"

echo "smtp/test: Tests runner for smtp"
CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh smtp > "$OUTPUT_ROOT/00.json"
CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh smtp --send-helo > "$OUTPUT_ROOT/helo.01.json"
CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh smtp --send-helo --helo-domain localhost > "$OUTPUT_ROOT/helo.02.json"
CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh smtp --send-ehlo > "$OUTPUT_ROOT/ehlo.03.json"
CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh smtp --ehlo-domain localhost > "$OUTPUT_ROOT/ehlo.04.json"
CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh smtp --send-ehlo --ehlo-domain localhost --send-quit > "$OUTPUT_ROOT/ehlo.quit.05.json"
CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh smtp --send-help --send-quit > "$OUTPUT_ROOT/help.quit.06.json"
# TODO: the qpsmtpd container does not support STARTTLS.

FIELDS="help quit helo ehlo"
status=0
for field in $FIELDS; do
    for file in $(find $OUTPUT_ROOT -iname "*$field*.json"); do
        echo "check $file for $field"
        RESULT=$(jp data.smtp.result.$field < $file)
        if [ "$RESULT" = "null" ]; then
            echo "Did not find $field in $file [["
            cat $file
            echo "]]"
            status=1
        fi
    done
done

# Dump the docker logs
echo "smtp/test: BEGIN docker logs from $CONTAINER_NAME [{("
docker logs --tail all $CONTAINER_NAME
echo ")}] END docker logs from $CONTAINER_NAME"

exit $status
