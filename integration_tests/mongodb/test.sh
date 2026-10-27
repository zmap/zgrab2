#!/usr/bin/env bash

set -e

versions="3.2.20 3.6.6 4.0.1 4.1.2"

MODULE_DIR=$(dirname $0)
ZGRAB_ROOT=$(git rev-parse --show-toplevel)
ZGRAB_OUTPUT=$ZGRAB_ROOT/zgrab-output

mkdir -p $ZGRAB_OUTPUT/mongodb


echo "mongodb/test: Tests runner for mongodb"

for version in $versions; do
    CONTAINER_NAME=zgrab_mongodb-${version}
    echo "mongodb/test: Testing $CONTAINER_NAME"
    CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh mongodb > "$ZGRAB_OUTPUT/mongodb/${version}-normal.json"
    # Dump the docker logs
    echo "#{MODULE_NAME}/test: BEGIN docker logs from $CONTAINER_NAME [{("
    docker logs --tail all $CONTAINER_NAME
    echo ")}] END docker logs from $CONTAINER_NAME"
done

CONTAINER_NAME=zgrab_mongodb-4.0.1-tls
echo "mongodb/test: Testing $CONTAINER_NAME"
CONTAINER_NAME=$CONTAINER_NAME "$ZGRAB_ROOT/docker-runner/docker-run.sh" mongodb --tls > "$ZGRAB_OUTPUT/mongodb/4.0.1-tls.json"

CONTAINER_NAME=$CONTAINER_NAME "$ZGRAB_ROOT/docker-runner/docker-run.sh" mongodb --tls --allow-tls-downgrade > "$ZGRAB_OUTPUT/mongodb/4.0.1-tls-downgrade-tls.json"
CONTAINER_NAME=zgrab_mongodb-4.0.1 "$ZGRAB_ROOT/docker-runner/docker-run.sh" mongodb --tls --allow-tls-downgrade > "$ZGRAB_OUTPUT/mongodb/4.0.1-tls-downgrade-plaintext.json"

python3 - "$ZGRAB_OUTPUT/mongodb/4.0.1-tls.json" \
    "$ZGRAB_OUTPUT/mongodb/4.0.1-tls-downgrade-tls.json" \
    "$ZGRAB_OUTPUT/mongodb/4.0.1-tls-downgrade-plaintext.json" <<'PY'
import json
import sys

for filename in sys.argv[1:]:
    with open(filename) as output:
        scan = json.load(output)["data"]["mongodb"]

    if scan["status"] != "success":
        sys.exit(f"mongodb/test: Scan failed in {filename}: {scan}")

    result = scan["result"]
    if result["build_info"]["version"] != "4.0.1":
        sys.exit(f"mongodb/test: Unexpected server version in {filename}: {result['build_info']}")
    if result["is_master"]["is_master"] is not True:
        sys.exit(f"mongodb/test: Unexpected isMaster response in {filename}: {result['is_master']}")
    if not result["database_info"]["databases"]:
        sys.exit(f"mongodb/test: No databases returned in {filename}: {result['database_info']}")

    if filename.endswith("-plaintext.json"):
        if "tls" in result:
            sys.exit(f"mongodb/test: Unexpected TLS log after plaintext fallback in {filename}")
    else:
        tls = result.get("tls", {})
        if tls.get("handshake_completed_successfully") is not True:
            sys.exit(f"mongodb/test: No successful TLS handshake logged in {filename}")
        handshake = tls.get("handshake_log", {})
        if not handshake.get("server_hello") or not handshake.get("server_certificates"):
            sys.exit(f"mongodb/test: Missing TLS server hello or certificates in {filename}")
PY

echo "mongodb/test: BEGIN docker logs from $CONTAINER_NAME [{("
docker logs --tail all "$CONTAINER_NAME"
echo ")}] END docker logs from $CONTAINER_NAME"
