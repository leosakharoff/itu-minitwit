#!/usr/bin/env bash

if [ "$1" = "init" ]; then

    echo "Resetting database at /tmp/minitwit.db..."
    rm -f /tmp/minitwit.db
    echo "Done. The app will recreate tables on next start."
elif [ "$1" = "start" ]; then
    echo "Starting minitwit..."
    nohup go run . > /tmp/out.log 2>&1 &
elif [ "$1" = "stop" ]; then
    echo "Stopping minitwit..."
    pkill -f minitwit
elif [ "$1" = "inspectdb" ]; then
    go run flag_tool.go -i | less
elif [ "$1" = "flag" ]; then
    go run flag_tool.go "$@"
else
  echo "I do not know this command..."
fi
