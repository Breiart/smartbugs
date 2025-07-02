#!/bin/sh

FILENAME="$1"
TIMEOUT="$2"
BIN="$3"
ARGS="${4:-}"

export PATH="$BIN:$PATH"
chmod +x "$BIN/solc"

semgrep --config ./solidity "$FILENAME" $ARGS
