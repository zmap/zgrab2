#!/usr/bin/env bash

set -e
python3 ./http_version_tests/test.py
python3 ./http_smoke_test/test.py
