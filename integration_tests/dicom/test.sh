#!/usr/bin/env bash

set -e
MODULE_DIR=$(dirname $0)
ZGRAB_ROOT=$(git rev-parse --show-toplevel)
ZGRAB_OUTPUT=$ZGRAB_ROOT/zgrab-output

mkdir -p $ZGRAB_OUTPUT/dicom

CONTAINER_NAME=zgrab_dicom

OUTPUT_FILE=$ZGRAB_OUTPUT/dicom/dicom.json

echo "dicom/test: Tests runner for DICOM"
# TODO FIXME: Add any necessary flags or additional tests
CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh dicom > $OUTPUT_FILE

# Dump the docker logs
echo "dicom/test: BEGIN docker logs from $CONTAINER_NAME [{("
docker logs --tail all $CONTAINER_NAME
echo ")}] END docker logs from $CONTAINER_NAME"

# TODO: If there are any other relevant log files, dump those to stdout here.
