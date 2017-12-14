#!/bin/bash +e

# Clean up after running the integration tests.
# Drop your cleanup script(s) in integration_tests/<protocol>/cleanup(.*).sh

echo "Cleaning up integration tests..."

pushd integration_tests
for mod in $(ls); do
    if [ -d "$mod" ]; then
        pushd $mod
        for cleanup in $(ls cleanup*.sh); do
            echo "Cleaning up $mod (integration_tests/$mod/$cleanup)..."
            if ! $cleanup; then
                echo "Warning: cleanup for $mod/$cleanup failed with exit code $?"
            fi
        done
        popd
    fi
done
popd

echo "Integration test cleanup finished."
