#!/bin/bash -e

# Set up the integration tests for all modules.
# Drop your setup script(s) in integration_tests/<protocol>/setup(.*).sh

echo "Setting up integration tests..."

pushd integration_tests
for mod in $(ls); do
    if [ -d "$mod" ]; then
        pushd $mod
        for setup in $(ls setup*.sh); do
            echo "Setting up $mod (integration_tests/$mod/$setup)..."
            $setup
        done
        popd
    fi
done
popd

echo "Integration tests setup finished."
