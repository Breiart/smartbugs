#!/bin/sh

FILENAME="$1"
ARGS="${2:-}"

cd /conkas

if [ -n "$ARGS" ]; then
    python3 conkas.py -fav "$FILENAME" $ARGS
else
    python3 conkas.py -fav "$FILENAME"
fi