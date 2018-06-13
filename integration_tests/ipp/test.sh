#!/usr/bin/env bash

set -e
MODULE_DIR=$(dirname $0)
ZGRAB_ROOT=$MODULE_DIR/../..
ZGRAB_OUTPUT=$ZGRAB_ROOT/zgrab-output

mkdir -p $ZGRAB_OUTPUT/ipp

CONTAINER_NAME=zgrab_ipp

OUTPUT_FILE=$ZGRAB_OUTPUT/ipp/ipp.json

echo "ipp/test: Testing IPP on $CONTAINER_NAME..."
# TODO FIXME: Add any necessary flags or additional tests
CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh ipp > $OUTPUT_FILE
# TODO: Add version with TLS flag when that's implemented

# Dump the docker logs
echo "ipp/test: BEGIN docker logs from $CONTAINER_NAME [{("
docker logs --tail all $CONTAINER_NAME
echo ")}] END docker logs from $CONTAINER_NAME"

# TODO: If there are any other relevant log files, dump those to stdout here.
# FIXME: Only dump these logs if they exist
#echo "ipp/test: BEGIN cups logs from $CONTAINER_NAME [{("
#docker exec -t $CONTAINER_NAME cat //var/log/cups/access_log
#echo ")}] END cups logs from $CONTAINER_NAME"

#echo "ipp/test: BEGIN cups logs from $CONTAINER_NAME [{("
#docker exec -t $CONTAINER_NAME cat //var/log/cups/error_log
#echo ")}] END cups logs from $CONTAINER_NAME"

#echo "ipp/test: BEGIN cups logs from $CONTAINER_NAME [{("
#docker exec -t $CONTAINER_NAME cat //var/log/cups/page_log
#echo ")}] END cups logs from $CONTAINER_NAME"