#!/usr/bin/env bash

set -e

SSH_PORT=33022
CONTAINER_NAME="sshtest"

# Run the SSH-specific integration tests:
# 1. Run zgrab2 on localhost:$SSH_PORT

if [ -z $ZGRAB_ROOT ] || [ -z $ZGRAB_OUTPUT ]; then
    echo "Must set ZGRAB_ROOT and ZGRAB_OUTPUT"
    exit 1
fi

mkdir -p $ZGRAB_OUTPUT/ssh

OUTPUT_FILE="$ZGRAB_OUTPUT/ssh/ssh.json"

echo "Testing SSH Version on local port $SSH_PORT..."
echo "127.0.0.1" | $ZGRAB_ROOT/cmd/zgrab2/zgrab2 ssh -p $SSH_PORT $* > $OUTPUT_FILE
