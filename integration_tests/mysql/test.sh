#!/usr/bin/env bash
set -e
MYSQL_VERSION=5.5 MYSQL_PORT=13306 ./single_run.sh
MYSQL_VERSION=5.6 MYSQL_PORT=23306 ./single_run.sh
MYSQL_VERSION=5.7 MYSQL_PORT=33306 ./single_run.sh
MYSQL_VERSION=8.0 MYSQL_PORT=43306 ./single_run.sh
