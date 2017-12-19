#!/bin/bash -e

# Start all of the MySQL docker containers, and wait for them start responding on port 3306

echo "Launching docker containers..."
# NOTE: the 5.5 and 5.6 versions do not have SSL enabled
CONTAINER_NAME=testmysql-5.5 MYSQL_VERSION=5.5 MYSQL_PORT=13306 ./util/launch_mysql_container.sh
CONTAINER_NAME=testmysql-5.6 MYSQL_VERSION=5.6 MYSQL_PORT=23306 ./util/launch_mysql_container.sh
CONTAINER_NAME=testmysql-5.7 MYSQL_VERSION=5.7 MYSQL_PORT=33306 ./util/launch_mysql_container.sh
CONTAINER_NAME=testmysql-8.0 MYSQL_VERSION=8.0 MYSQL_PORT=43306 ./util/launch_mysql_container.sh

echo "Waiting for MySQL to start up on all containers..."
CONTAINER_NAME=testmysql-5.5 MYSQL_PORT=13306 ./util/wait_for_mysqld.sh
CONTAINER_NAME=testmysql-5.6 MYSQL_PORT=23306 ./util/wait_for_mysqld.sh
CONTAINER_NAME=testmysql-5.7 MYSQL_PORT=33306 ./util/wait_for_mysqld.sh
CONTAINER_NAME=testmysql-8.0 MYSQL_PORT=43306 ./util/wait_for_mysqld.sh
