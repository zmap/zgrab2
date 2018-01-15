#!/usr/bin/env bash

# Keep cleaning up, even if something fails
set +e

# Clean up after running the integration tests.
# Drop your cleanup script(s) in integration_tests/<protocol>/cleanup(.*).sh

# Run from root of project
TEST_DIR=$(dirname "$0")
cd "$TEST_DIR/.."

echo "Cleaning up integration tests..."

pushd integration_tests
for mod in $(ls); do
    if [ -d "$mod" ]; then
        pushd $mod
        for cleanup in $(ls cleanup*.sh); do
            echo "Cleaning up $mod (integration_tests/$mod/$cleanup)..."
            if ! ./$cleanup; then
                echo "Warning: cleanup for $mod/$cleanup failed with exit code $?"
            fi
        done
        popd
    fi
done
popd

echo "Integration test cleanup finished."
