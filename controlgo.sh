#!/usr/bin/env bash

if [ "$1" = "init" ]; then
    if [ -f "/tmp/minitwit.db" ]; then
        echo "Database already exists."
        exit 1
    fi
    echo "Initializing database..."
    go run main.go --initdb

elif [ "$1" = "start" ]; then
    echo "Starting minitwit..."
    nohup go run main.go > /tmp/out.log 2>&1 &

elif [ "$1" = "stop" ]; then
    echo "Stopping minitwit..."
    pkill -x main

elif [ "$1" = "inspectdb" ]; then
    ./flag_tool -i | less

elif [ "$1" = "flag" ]; then
    ./flag_tool "$@"

else
    echo "I do not know this command..."
fi

