#!/usr/bin/env bash

set -e
MODULE_DIR=$(dirname $0)
ZGRAB_ROOT=$(git rev-parse --show-toplevel)
ZGRAB_OUTPUT=$ZGRAB_ROOT/zgrab-output

OUTPUT_ROOT=$ZGRAB_OUTPUT/ipp

mkdir -p $ZGRAB_OUTPUT/ipp

versions="cups cups-tls"

function test_cups() {
    echo "ipp/test: Tests runner for ipp_cups"

    CONTAINER_NAME="zgrab_ipp_cups" $ZGRAB_ROOT/docker-runner/docker-run.sh ipp --timeout 3s --verbose > "$OUTPUT_ROOT/cups.json"
    # FIXME: No good reason to use a tmp file & saved file, b/c I'm not testing any failure states yet
    #CONTAINER_NAME="zgrab_ipp_cups" $ZGRAB_ROOT/docker-runner/docker-run.sh ipp --timeout 3 --verbose > out.tmp
    major=$(jp -u data.ipp.result.version_major < "$OUTPUT_ROOT/cups.json")
    minor=$(jp -u data.ipp.result.version_minor < "$OUTPUT_ROOT/cups.json")
    cups=$(jp -u data.ipp.result.cups_version < "$OUTPUT_ROOT/cups.json")
    rm -f out.tmp
    if ! [ $major = "2" ]; then
        echo "ipp/test: Incorrect major version. Expected 2, got $major"
        exit 1
    fi
    if ! [ $minor = "1" ]; then
        echo "ipp/test: Incorrect minor version. Expected 1, got $minor"
        exit 1
    fi
    if ! [ $cups = "CUPS/2.1" ]; then
        echo "ipp/test: Incorrect CUPS version. Expected CUPS/2.1, got $cups"
        exit 1
    fi
}

function test_cups_tls() {
    echo "ipp/test: Tests runner for ipp_cups-tls"

    CONTAINER_NAME="zgrab_ipp_cups-tls" $ZGRAB_ROOT/docker-runner/docker-run.sh ipp --timeout 3s --ipps --verbose > "$OUTPUT_ROOT/cups-tls.json"
    # FIXME: No good reason to use a tmp file & saved file, b/c I'm not testing any failure states yet
    #CONTAINER_NAME="zgrab_ipp_cups-tls" $ZGRAB_ROOT/docker-runner/docker-run.sh ipp --timeout 3 --ipps --verbose > out.tmp
    major=$(jp -u data.ipp.result.version_major < "$OUTPUT_ROOT/cups-tls.json")
    minor=$(jp -u data.ipp.result.version_minor < "$OUTPUT_ROOT/cups-tls.json")
    response=$(jp -u data.ipp.result.response < "$OUTPUT_ROOT/cups-tls.json")
    cups=$(jp -u data.ipp.result.cups_version < "$OUTPUT_ROOT/cups-tls.json")
    # TODO: Check for a particular field in the tls object, since it may be safer
    tls=$(jp -u data.ipp.result.tls < "$OUTPUT_ROOT/cups-tls.json")
    #rm -f out.tmp
    if ! [ $major = "2" ]; then
        echo "ipp/test: Incorrect major version. Expected 2, got $major"
        exit 1
    fi
    if ! [ $minor = "1" ]; then
        echo "ipp/test: Incorrect minor version. Expected 1, got $minor"
        exit 1
    fi
    if ! [ $cups = "CUPS/2.1" ]; then
        echo "ipp/test: Incorrect CUPS version. Expected CUPS/2.1, got $cups"
        exit 1
    fi
    if [ "$tls" = "null" ]; then
        echo "ipp/test: No TLS handshake logged"
        exit 1
    fi
}

echo "ipp/test: Testing IPP..."
test_cups
test_cups_tls


for version in $versions; do
    CONTAINER_NAME="zgrab_ipp_$version"

    # Dump the docker logs
    echo "ipp/test: BEGIN docker logs from $CONTAINER_NAME [{("
    docker logs --tail all $CONTAINER_NAME
    echo ")}] END docker logs from $CONTAINER_NAME"

    # TODO: If there are any other relevant log files, dump those to stdout here.
    # FIXME: Only dump these 3 logs if they exist
    #echo "ipp/test: BEGIN cups logs from $CONTAINER_NAME [{("
    #docker exec $CONTAINER_NAME cat //var/log/cups/access_log
    #echo ")}] END cups logs from $CONTAINER_NAME"

    #echo "ipp/test: BEGIN cups logs from $CONTAINER_NAME [{("
    #docker exec $CONTAINER_NAME cat //var/log/cups/error_log
    #echo ")}] END cups logs from $CONTAINER_NAME"

    #echo "ipp/test: BEGIN cups logs from $CONTAINER_NAME [{("
    #docker exec $CONTAINER_NAME cat //var/log/cups/page_log
    #echo ")}] END cups logs from $CONTAINER_NAME"
done
