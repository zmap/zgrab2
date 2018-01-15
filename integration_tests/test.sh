#!/usr/bin/env bash

set -e

# Do all integration tests for all protocols
# To add tests for a new protocol, run `./integration_tests/new.sh <new_protocol>` and implement the appropriate test scripts.

# Run from root of project
TEST_DIR=$(dirname "$0")
ZGRAB_ROOT="$TEST_DIR/.."
cd "$ZGRAB_ROOT"

ZGRAB_OUTPUT="$ZGRAB_ROOT/zgrab-output"

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
            err="schema failure@$protocol/$outfile"
            if [[ $status -eq 0 ]]; then
                failures="$err"
            else
                failures="$failures, $err"
            fi
            status=1
        else
            echo "validation of $target succeeded."
            scan_status=$($ZGRAB_ROOT/jp -u data.${protocol}.status < $target)
            if ! [ $scan_status = "success" ]; then
                echo "Scan returned success=$scan_status for $protocol/$outfile"
                err="scan failure(${scan_status})@$protocol/$outfile"
                if [[ $status -eq 0 ]]; then
                    failures="$err"
                else
                    failures="$failures, $err"
                fi
                status=1
            fi
        fi
    done
done

if [ -n "$failures" ]; then
    echo "One or more schema validations failed: $failures"
fi

exit $status
