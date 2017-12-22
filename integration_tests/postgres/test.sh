#!/usr/bin/env bash

set -e

mkdir -p $ZGRAB_OUTPUT/postgres

echo "127.0.0.1" | $ZGRAB_ROOT/cmd/zgrab2/zgrab2 postgres -p 45432 --timeout 10 $* > $ZGRAB_OUTPUT/postgres/9.3-nossl.json
echo "127.0.0.1" | $ZGRAB_ROOT/cmd/zgrab2/zgrab2 postgres -p 45433 --timeout 10 $* > $ZGRAB_OUTPUT/postgres/9.4-nossl.json
echo "127.0.0.1" | $ZGRAB_ROOT/cmd/zgrab2/zgrab2 postgres -p 45434 --timeout 10 $* > $ZGRAB_OUTPUT/postgres/9.5-nossl.json
echo "127.0.0.1" | $ZGRAB_ROOT/cmd/zgrab2/zgrab2 postgres -p 45435 --timeout 10 $* > $ZGRAB_OUTPUT/postgres/9.6-nossl.json
echo "127.0.0.1" | $ZGRAB_ROOT/cmd/zgrab2/zgrab2 postgres -p 45436 --timeout 10 $* > $ZGRAB_OUTPUT/postgres/10.1-nossl.json

echo "127.0.0.1" | $ZGRAB_ROOT/cmd/zgrab2/zgrab2 postgres -p 35432 --timeout 10 $* > $ZGRAB_OUTPUT/postgres/9.3-ssl.json
echo "127.0.0.1" | $ZGRAB_ROOT/cmd/zgrab2/zgrab2 postgres -p 35433 --timeout 10 $* > $ZGRAB_OUTPUT/postgres/9.4-ssl.json
echo "127.0.0.1" | $ZGRAB_ROOT/cmd/zgrab2/zgrab2 postgres -p 35434 --timeout 10 $* > $ZGRAB_OUTPUT/postgres/9.5-ssl.json
echo "127.0.0.1" | $ZGRAB_ROOT/cmd/zgrab2/zgrab2 postgres -p 35435 --timeout 10 $* > $ZGRAB_OUTPUT/postgres/9.6-ssl.json
echo "127.0.0.1" | $ZGRAB_ROOT/cmd/zgrab2/zgrab2 postgres -p 35436 --timeout 10 $* > $ZGRAB_OUTPUT/postgres/10.1-ssl.json
