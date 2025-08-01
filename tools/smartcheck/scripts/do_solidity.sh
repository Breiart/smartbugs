#!/bin/sh

FILENAME="$1"
BIN="$2"
ARGS="${3:-}"

export PATH="$BIN:$PATH"
chmod +x "$BIN/solc"

if [ -n "$ARGS" ]; then
    smartcheck -p "$FILENAME" $ARGS
else
    smartcheck -p "$FILENAME"
fi
