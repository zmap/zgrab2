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

    CONTAINER_NAME="zgrab_ntp_openntp" $ZGRAB_ROOT/docker-runner/docker-run.sh ntp --timeout 3s > "$OUTPUT_ROOT/openntp.json"
    
    # Don't drop this in the standard output root, since it will not have status = success
    CONTAINER_NAME="zgrab_ntp_openntp" $ZGRAB_ROOT/docker-runner/docker-run.sh ntp --timeout 3s --monlist > out.tmp
    time=$(jp -u data.ntp.result.time < out.tmp)
    version=$(jp -u data.ntp.result.version < out.tmp)
    rm -f out.tmp
    if [ $time = "null" ]; then
        echo "ntp/test: Failed to get partial result from monlist on openntp (time = null)"
        exit 1
    fi
    if ! [ $version = "3" ]; then
        echo "ntp/test: Failed to get partial result from monlist on openntp (version = $version)"
        exit 1
    fi
}

function test_bad_req() {
    code=$1
    expected_error=$2
    CONTAINER_NAME="zgrab_ntp_4.2.6" $ZGRAB_ROOT/docker-runner/docker-run.sh ntp --timeout 3s --monlist --request-code $code --skip-get-time > out.tmp
    status=$(jp -u data.ntp.status < out.tmp)
    error=$(jp -u data.ntp.error < out.tmp)
    rm -f out.tmp
    if ! [ $status = "application-error" ]; then
        echo "ntp/test: Got error '$error', expected '$expected_error' on $code"
        exit 1
    fi
    if ! [ $error = $expected_error ]; then
        echo "ntp/test: Got error '$error', expected '$expected_error' on $code"
        exit 1
    fi
}

function test_4_2_6() {
    CONTAINER_NAME="zgrab_ntp_4.2.6"

    echo "ntp/test: Tests runner for ntp_4.2.6"

    CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh ntp --timeout 3s > "$OUTPUT_ROOT/4.2.6_normal.json"
    CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh ntp --timeout 3s --monlist > "$OUTPUT_ROOT/4.2.6_monlist.json"

    request_codes="REQ_MON_GETLIST_1 REQ_MON_GETLIST"
    for code in $request_codes; do
        CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh ntp --timeout 3s --monlist --request-code $code > "$OUTPUT_ROOT/4.2.6_$code.json"
        CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh ntp --timeout 3s --monlist --request-code $code --skip-get-time > "$OUTPUT_ROOT/4.2.6_${code}_solo.json"
    done

    # Check that when the server returns with a valid error code that we return status = application-error and we forward the INFO_ERR code from the server
    test_bad_req "REQ_PEER_LIST" "INFO_ERR_NODATA"
    test_bad_req "REQ_DO_DIRTY_HACK" "INFO_ERR_REQ"
    test_bad_req "REQ_DONT_DIRTY_HACK" "INFO_ERR_REQ"
}

test_openntp

test_4_2_6

for version in $versions; do
    CONTAINER_NAME="zgrab_ntp_$version"

    echo "ntp/test: BEGIN docker logs from $CONTAINER_NAME [{("
    docker logs --tail all $CONTAINER_NAME
    echo ")}] END docker logs from $CONTAINER_NAME"
done
