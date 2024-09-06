#!/bin/bash

# Find the running service docker container
CON_NAME=$(docker ps --filter ancestor=someip-service --format '{{.Names}}')

docker exec -it $CON_NAME /bin/bash
