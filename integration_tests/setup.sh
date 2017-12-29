#!/usr/bin/env bash

set -e

# Set up the integration tests for all modules.
# Drop your setup script(s) in integration_tests/<protocol>/setup(.*).sh

# Run from root of project
TEST_DIR=$(dirname "$0")
ZGRAB_ROOT="$TEST_DIR/.."
cd "$ZGRAB_ROOT"

echo "Building zgrab2_runner docker image..."
./docker-runner/build-runner.sh

echo "Setting up integration tests..."

pushd integration_tests
for mod in $(ls); do
  if [ -d "$mod" ]; then
    pushd $mod
    for setup in $(ls setup*.sh); do
      echo "Setting up $mod (integration_tests/$mod/$setup)..."
      ./$setup
    done
    popd
  fi
done
popd

echo "Integration tests setup finished."
