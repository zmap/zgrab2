#!/usr/bin/env bash

echo "mqtt/setup: Tests setup for mqtt"

CONTAINER_TAG="eclipse-mosquitto"
CONTAINER_NAME="zgrab_mqtt"

# If the container is already running, use it.
if docker ps --filter "name=$CONTAINER_NAME" | grep -q $CONTAINER_NAME; then
    echo "mqtt/setup: Container $CONTAINER_NAME already running -- nothing to setup"
    exit 0
fi

DOCKER_RUN_FLAGS="--rm --name $CONTAINER_NAME -td -v ./mosquitto.conf:/mosquitto/config/mosquitto.conf -v ./server.pem:/mosquitto/server.pem -v ./server.key:/mosquitto/server.key"

# If it is not running, try launching it -- on success, use that. 
echo "mqtt/setup: Trying to launch $CONTAINER_NAME..."
if ! docker run $DOCKER_RUN_FLAGS $CONTAINER_TAG; then
    echo "eclipse-mosquitto launch fail"

    #echo "mqtt/setup: Building docker image $CONTAINER_TAG..."
    # If it fails, build it from ./container/Dockerfile
    #docker build -t $CONTAINER_TAG ./container
    # Try again
    #echo "mqtt/setup: Launching $CONTAINER_NAME..."
    #docker run $DOCKER_RUN_FLAGS $CONTAINER_TAG
fi
