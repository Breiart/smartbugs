#!/bin/sh

FILENAME="$1"
BIN="$2"
ARGS="${3:-}"

export PATH="$BIN:$PATH"
chmod +x "$BIN/solc"

mkdir /results
if [ -n "$ARGS" ]; then
    java -Xmx16G -jar /securify_jar/securify.jar --output /results.json -fs "$FILENAME" $ARGS
else
    java -Xmx16G -jar /securify_jar/securify.jar --output /results.json -fs "$FILENAME"
fi
