#!/usr/bin/env bash

# This is the entrypoint for the zgrab2_runner container.
# Runs the zgrab2 binary, passing along any arguments, with stdin containing the single line: the ZGRAB_TARGET.

set -e

cd /go/src/github.com/zmap/zgrab2

if ! [ -x $ZGRAB_REBUILD ]; then
  if ! [ -x $ZGRAB_BRANCH ]; then
    git checkout $ZGRAB_BRANCH
  fi
  git pull
  make
fi

set -x
echo $ZGRAB_TARGET | /go/src/github.com/zmap/zgrab2/cmd/zgrab2/zgrab2 $*
