#!/usr/bin/env bash

set -euo pipefail

ZGRAB_ROOT=$(git rev-parse --show-toplevel)
OUTPUT_ROOT="$ZGRAB_ROOT/zgrab-output/snmp"
mkdir -p "$OUTPUT_ROOT"

CONTAINER_NAME=zgrab_snmp "$ZGRAB_ROOT/docker-runner/docker-run.sh" \
    snmp --version auto --target-timeout 1s > "$OUTPUT_ROOT/v1-fallback.json"

version=$(jp -u data.snmp.result.version < "$OUTPUT_ROOT/v1-fallback.json")
if [ "$version" != "1" ]; then
    echo "snmp/test: expected auto mode to fall back to SNMPv1, got $version"
    exit 1
fi
