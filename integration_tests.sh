#!/bin/bash -e

# Do all integration tests for all protocols
# To add tests for a new protocol, create a directory integration_tests/<new_protocol>, and drop its setup.sh, test.sh, and cleanup.sh there.

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

echo "Doing schema validation..."
for protocol in $(ls $ZGRAB_OUTPUT); do
    for outfile in $(ls $ZGRAB_OUTPUT/$protocol); do
        target="$ZGRAB_OUTPUT/$protocol/$outfile"
        echo "Validating $target [{("
        cat $target
        echo ")}]:"
        python -m zschema validate schemas/__init__.py:zgrab2 $target
        echo "validation of $target succeeded."
    done
done
