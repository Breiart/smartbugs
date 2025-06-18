#!/bin/sh

FILENAME="$1"
BIN="$2"
ARGS="${3:-}"

mkdir /results

if [ -n "$ARGS" ]; then
    java -Xmx16G -jar /securify_jar/securify.jar --livestatusfile /results/live.json --output /results/results.json -fh "$FILENAME" $ARGS
else
    java -Xmx16G -jar /securify_jar/securify.jar --livestatusfile /results/live.json --output /results/results.json -fh "$FILENAME"
fi