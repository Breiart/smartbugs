#!/bin/sh

FILENAME="$1"
ARGS="${2:-}"

cd /MAIAN/tool

if [ -n "$ARGS" ]; then
    python3 maian.py -b "$FILENAME" $ARGS
else
    python3 maian.py -c 0 -b "$FILENAME"
    python3 maian.py -c 1 -b "$FILENAME"
    python3 maian.py -c 2 -b "$FILENAME"
fi