#!/usr/bin/env bash

set -e
MODULE_DIR=$(dirname $0)
TEST_ROOT=$MODULE_DIR/..
ZGRAB_ROOT=$MODULE_DIR/../..
ZGRAB_OUTPUT=$ZGRAB_ROOT/zgrab-output
OUTPUT_ROOT=$ZGRAB_OUTPUT/ntp

mkdir -p $OUTPUT_ROOT

versions="openntp 4.2.6"

function test_openntp() {
    echo "ntp/test: Tests runner for ntp_openntp"

    CONTAINER_NAME="zgrab_ntp_openntp" $ZGRAB_ROOT/docker-runner/docker-run.sh ntp > "$OUTPUT_ROOT/openntp.json"
}

function test_4_2_6() {
    CONTAINER_NAME="zgrab_ntp_4.2.6"

    echo "ntp/test: Tests runner for ntp_4.2.6"

    CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh ntp > "$OUTPUT_ROOT/4.2.6_normal.json"
    CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh ntp --monlist > "$OUTPUT_ROOT/4.2.6_monlist.json"

    request_codes="REQ_PEER_LIST REQ_DO_DIRTY_HACK REQ_DONT_DIRTY_HACK REQ_MON_GETLIST_1 REQ_MON_GETLIST"
    for code in $request_codes; do
        CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh ntp --monlist --request-code $code > "$OUTPUT_ROOT/4.2.6_$code.json"
    done
}

test_openntp

test_4_2_6
