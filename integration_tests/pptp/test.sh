#!/usr/bin/env bash

set -e
MODULE_DIR=$(dirname $0)
ZGRAB_ROOT=$(git rev-parse --show-toplevel)
ZGRAB_OUTPUT=$ZGRAB_ROOT/zgrab-output

mkdir -p $ZGRAB_OUTPUT/pptp

CONTAINER_NAME=zgrab_pptp

OUTPUT_FILE=$ZGRAB_OUTPUT/pptp/pptp.json

echo "pptp/test: Tests runner for pptp"
CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh pptp > $OUTPUT_FILE

python3 - "$OUTPUT_FILE" <<'PY'
import json
import sys

with open(sys.argv[1]) as output:
    scan = json.load(output)["data"]["pptp"]

if scan["status"] != "success":
    sys.exit(f"pptp/test: expected success, got {scan['status']}: {scan.get('error')}")

result = scan["result"]
for field, expected in (
    ("protocol_version", 0x0100),
    ("result_code", 1),
    ("error_code", 0),
    ("framing_capability", 0),
    ("bearer_capability", 0),
    ("maximum_channels", 1),
    ("firmware_revision", 1),
):
    if type(result.get(field)) is not int or result[field] != expected:
        sys.exit(f"pptp/test: expected {field}={expected}, got {result.get(field)!r}")

for field, expected in (("hostname", "local"), ("vendor", "linux")):
    if result.get(field) != expected:
        sys.exit(f"pptp/test: expected {field}={expected!r}, got {result.get(field)!r}")

for field in ("banner", "control_message"):
    if not isinstance(result.get(field), str) or not result[field]:
        sys.exit(f"pptp/test: missing raw {field}")

print("pptp/test: structured SCCRP fields present")
PY

# Dump the docker logs
echo "pptp/test: BEGIN docker logs from $CONTAINER_NAME [{("
docker logs --tail all $CONTAINER_NAME
echo ")}] END docker logs from $CONTAINER_NAME"

# TODO: If there are any other relevant log files, dump those to stdout here.
