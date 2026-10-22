#!/usr/bin/env bash

set -e
MODULE_DIR=$(dirname $0)
ZGRAB_ROOT=$(git rev-parse --show-toplevel)
ZGRAB_OUTPUT=$ZGRAB_ROOT/zgrab-output

mkdir -p $ZGRAB_OUTPUT/ldap

CONTAINER_NAME=zgrab_ldap

OUTPUT_ROOT=$ZGRAB_OUTPUT/ldap

echo "ldap/test: Tests runner for ldap"

# Test 1: Plain LDAP with auto-detection disabled (port 389, no TLS)
echo "ldap/test: Testing plain LDAP on port 389 (no auto-STARTTLS)..."
CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh ldap --no-starttls-auto > $OUTPUT_ROOT/plain.json

# Test 2: LDAPS (implicit TLS on port 636)
echo "ldap/test: Testing LDAPS on port 636..."
CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh ldap --ldaps -p 636 > $OUTPUT_ROOT/ldaps.json

# Test 3: Forced STARTTLS (upgrade on port 389)
echo "ldap/test: Testing forced STARTTLS on port 389..."
CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh ldap --starttls > $OUTPUT_ROOT/starttls.json

# Test 4: Auto-detect STARTTLS (default behavior, port 389)
echo "ldap/test: Testing auto-detect STARTTLS on port 389..."
CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh ldap > $OUTPUT_ROOT/auto.json

# Dump the docker logs
echo "ldap/test: BEGIN docker logs from $CONTAINER_NAME [{("
docker logs --tail all $CONTAINER_NAME
echo ")}] END docker logs from $CONTAINER_NAME"

# Validate results
status=0

function checkField() {
    local file=$1
    local field=$2
    echo "check $file for $field"
    RESULT=$(jp data.ldap.result.$field < $file)
    if [ "$RESULT" = "null" ]; then
        echo "Did not find $field in $file [["
        cat $file
        echo "]]"
        status=1
    fi
}

function checkFileForLackOfField() {
    local file=$1
    local field=$2
    echo "check $file for lack of $field"
    RESULT=$(jp data.ldap.result.$field < $file)
    if [ "$RESULT" != "null" ]; then
        echo "Unexpectedly found $field in $file [["
        cat $file
        echo "]]"
        status=1
    fi
}

# All modes should return operational Root DSE attributes, not just objectClass.
for file in $OUTPUT_ROOT/plain.json $OUTPUT_ROOT/ldaps.json $OUTPUT_ROOT/starttls.json $OUTPUT_ROOT/auto.json; do
    checkField $file naming_contexts
    checkField $file supported_ldap_version
    checkField $file supported_control
    checkField $file supported_extension
    checkField $file subschema_subentry
done

# LDAPS, forced STARTTLS, and auto-detect should have TLS log
checkField $OUTPUT_ROOT/ldaps.json tls
checkField $OUTPUT_ROOT/starttls.json tls
checkField $OUTPUT_ROOT/auto.json tls

# Plain LDAP (auto disabled) should NOT have TLS log
checkFileForLackOfField $OUTPUT_ROOT/plain.json tls

# Forced STARTTLS should have starttls_response
checkField $OUTPUT_ROOT/starttls.json starttls_response

# Auto-detect should also have starttls_response (server supports it)
checkField $OUTPUT_ROOT/auto.json starttls_response

exit $status
