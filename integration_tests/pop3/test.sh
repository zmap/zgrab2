#!/usr/bin/env bash

set -e
MODULE_DIR=$(dirname $0)
ZGRAB_ROOT=$(git rev-parse --show-toplevel)
ZGRAB_OUTPUT=$ZGRAB_ROOT/zgrab-output

mkdir -p $ZGRAB_OUTPUT/pop3

CONTAINER_NAME=zgrab_pop3

OUTPUT_ROOT=$ZGRAB_OUTPUT/pop3

echo "pop3/test: Tests runner for pop3"
CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh pop3 > $OUTPUT_ROOT/banner.json
CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh pop3 --send-quit > $OUTPUT_ROOT/banner.quit.json
CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh pop3 --send-help --send-quit > $OUTPUT_ROOT/help.banner.quit.json
CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh pop3 --send-noop --send-help --send-quit > $OUTPUT_ROOT/noop.help.banner.quit.json

# TODO: the pop3 container does not support STARTTLS; they suggest 
# wrapping it in stunnel (which would handle the --pop3s case).

FIELDS="help quit banner noop"
status=0
for field in $FIELDS; do
    for file in $(find $OUTPUT_ROOT -iname "*$field*.json"); do
        echo "check $file for $field"
        RESULT=$(jp data.pop3.result.$field < $file)
        if [ "$RESULT" = "null" ]; then
            echo "Did not find $field in $file [["
            cat $file
            echo "]]"
            status=1
        fi
    done
done

# Dump the docker logs
echo "pop3/test: BEGIN docker logs from $CONTAINER_NAME [{("
docker logs --tail all $CONTAINER_NAME
echo ")}] END docker logs from $CONTAINER_NAME"
