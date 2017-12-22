#!/usr/bin/env bash

set -e

# Do all integration tests for all protocols
# To add tests for a new protocol, run `./integration_tests/new.sh <new_protocol>` and implement the appropriate test scripts.

# Run from root of project
TEST_DIR=$(dirname "$0")
cd "$TEST_DIR/.."

# <protocol>_integration_tests.sh should drop its output into $ZGRAB_OUTPUT/<protocol>/* so that it can be validated
if [ -z $ZGRAB_OUTPUT ]; then
    ZGRAB_OUTPUT="$(pwd)/zgrab-output"
fi

export ZGRAB_OUTPUT=$ZGRAB_OUTPUT
export ZGRAB_ROOT=$(pwd)

pushd integration_tests
for mod in $(ls); do
    if [ -d "$mod" ]; then
        pushd $mod
        for test in $(ls test*.sh); do
            echo "Running integration_tests/$mod/$test"
            ./$test
        done
        popd
    fi
done
popd

status=0
failures=""
echo "Doing schema validation..."
for protocol in $(ls $ZGRAB_OUTPUT); do
    for outfile in $(ls $ZGRAB_OUTPUT/$protocol); do
        target="$ZGRAB_OUTPUT/$protocol/$outfile"
        echo "Validating $target [{("
        cat $target
        echo ")}]:"
        if ! python -m zschema validate schemas/__init__.py:zgrab2 $target; then
            echo "Schema validation failed for $protocol/$outfile"
            if [[ $status -eq 0 ]]; then
                failures="$protocol/$outfile"
            else
                failures="$failures, $protocol/$outfile"
            fi
            status=1
        else
            echo "validation of $target succeeded."
        fi
    done
done

if [ -n "$failures" ]; then
    echo "One or more schema validations failed: $failures"
fi

exit $status
