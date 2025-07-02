#!/bin/sh

FILENAME="$1"
BIN="$2"
ARGS="${3:-}"

export PATH="$BIN:$PATH"
chmod +x "$BIN/solc"

solhint -f unix "$FILENAME" $ARGS
