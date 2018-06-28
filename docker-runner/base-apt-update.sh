#!/usr/bin/env bash

# Run apt-get update on $IMAGE_ID then commit the changes.

: "${IMAGE_ID:?}"

set -e
CONTAINER_ID_FILE=$(mktemp)
rm $CONTAINER_ID_FILE
docker run --cidfile $CONTAINER_ID_FILE -it $IMAGE_ID apt-get update
CONTAINER_ID=$(cat $CONTAINER_ID_FILE)
rm $CONTAINER_ID_FILE
docker commit $CONTAINER_ID $IMAGE_ID
docker rm $CONTAINER_ID
