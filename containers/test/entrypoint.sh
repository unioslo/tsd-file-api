#!/bin/bash

CONFIG_FILE="$1"

/usr/local/bin/poetry install

if [ -z "$CONFIG_FILE" ]; then
    exec /usr/local/bin/tsd-file-api
else
    exec /usr/local/bin/tsd-file-api "$CONFIG_FILE"
fi
