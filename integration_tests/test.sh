#!/usr/bin/env bash

set -e
set -o pipefail

# Do all integration tests for all protocols
# To add tests for a new protocol, run `./integration_tests/new.sh <new_protocol>` and implement the appropriate test scripts.

# Test procedure:
# 1. For each module (subdirectory of integration_tests (%)):
#   a. Enter module directory
#   b. If there is a setup.sh, run it (*)
#   c. Run test.sh
#   d. If there is a cleanup.sh, run it (*)
# 2. For each JSON file in zgrab-output: (^)
#   a. Dump the file to stdout
#   b. Validate that the output matches the protocol's schema (using the parent folder name as the protocol)
#   c. Check that data.<protocol>.status == "success"
#
# (*) Skip if the NOSETUP environment variable is set
# (^) Skip if the NOSCHEMA environment variable is set
# (%) The .templates directory is skipped, and if the TEST_MODULES 
#     environment variables is set, only modules in that list are run

# Any errors in the first part will cause an immediate failure.
# During schema validation, all output is validated and the errors are dumped afterwards.
# In either case, a failure leads to a nonzero exit code.
# 

# Run from root of project
ZGRAB_ROOT=$(git rev-parse --show-toplevel)

cd "$ZGRAB_ROOT"

ZGRAB_OUTPUT="zgrab-output"

mkdir -p $ZGRAB_OUTPUT

if ! which jp; then
    echo "Please install jp"
    exit 1
fi

pushd integration_tests
for mod in $(ls); do
    if [ ".template" != "$mod" ] && [ -d "$mod" ] && ( [ -z $TEST_MODULES ] || [ $mod = *"$TEST_MODULES"* ]); then
        pushd $mod
        for test in $(ls test*.sh); do
            echo "Running integration_tests/$mod/$test"
            # Given test.x.sh, find setup.x.sh and cleanup.x.sh
            setup=${test/test/setup}
            cleanup=${test/test/cleanup}
            if [ -z $NOSETUP ] && [ -f $setup ]; then
                ./$setup
            fi
            ./$test
            if [ -z $NOSETUP ] && [ -f $cleanup ]; then
                ./$cleanup
            fi
        done
        popd
    fi
done
popd

if ! [ -z $NOSCHEMA ]; then
    echo "Skipping schema validation."
    exit 0
fi

status=0
failures=""
echo "Doing schema validation..."

for protocol in $(ls $ZGRAB_OUTPUT); do
    for outfile in $(ls $ZGRAB_OUTPUT/$protocol); do
        target="$ZGRAB_OUTPUT/$protocol/$outfile"
        echo "Validating $target [{("
        cat $target
        echo ")}]:"
        if ! python2 -m zschema validate zgrab2 $target --path . --module zgrab2_schemas.zgrab2 ; then
            echo "Schema validation failed for $protocol/$outfile"
            err="schema failure@$protocol/$outfile"
            if [[ $status -eq 0 ]]; then
                failures="$err"
            else
                failures="$failures, $err"
            fi
            status=1
        else
            scan_status=$(jp -u data.${protocol}.status < $target)
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
