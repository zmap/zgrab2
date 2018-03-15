#!/bin/sh

set -x

while true; do
    watch /usr/sbin/popa3d -D
    echo "popa3d exited unexpectedly. Restarting..."
    sleep 1
done
