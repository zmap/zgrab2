#!/bin/sh -e

# Do all integration tests for all protocols

if [ -z $ZSCHEMA_PATH ]; then
    ZSCHEMA_PATH="zschema"
fi

# <protocol>_integration_tests.sh should drop its output into $ZGRAB_OUTPUT/<protocol>/* so that it can be validated
if [ -z $ZGRAB_OUTPUT ]; then
    ZGRAB_OUTPUT="zgrab-output"
fi

echo "Doing MySQL integration tests..."
ZGRAB_OUTPUT=$ZGRAB_OUTPUT MYSQL_VERSION=5.5 MYSQL_PORT=13306 ./mysql_integration_tests.sh
ZGRAB_OUTPUT=$ZGRAB_OUTPUT MYSQL_VERSION=5.6 MYSQL_PORT=23306 ./mysql_integration_tests.sh
ZGRAB_OUTPUT=$ZGRAB_OUTPUT MYSQL_VERSION=5.7 MYSQL_PORT=33306 ./mysql_integration_tests.sh
ZGRAB_OUTPUT=$ZGRAB_OUTPUT MYSQL_VERSION=8.0 MYSQL_PORT=43306 ./mysql_integration_tests.sh

if [ -d $ZSCHEMA_PATH ]; then
    echo "Doing schema validation..."
    for protocol in $(ls $ZGRAB_OUTPUT); do
        for outfile in $(ls $ZGRAB_OUTPUT/$protocol); do
            target="$ZGRAB_OUTPUT/$protocol/$outfile"
            echo "Validating $target [{("
            cat $target
            echo ")}]:"
            PYTHONPATH=$ZSCHEMA_PATH python -m zschema validate schemas/__init__.py:zgrab2 $target
            echo "validation of $target succeeded."
        done
    done
else
    echo "Skipping schema validation: point ZSCHEMA_PATH to your zschema checkout to enable"
fi
