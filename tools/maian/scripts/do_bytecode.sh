#!/bin/sh

FILENAME="$1"
ARGS="${2:-}"

cd /MAIAN/tool

if [ -n "$ARGS" ]; then
    python3 maian.py -bs "$FILENAME" $ARGS
else
    python3 maian.py -c 0 -bs "$FILENAME"
    python3 maian.py -c 1 -bs "$FILENAME"
    python3 maian.py -c 2 -bs "$FILENAME"
fi