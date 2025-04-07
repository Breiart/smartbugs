#!/bin/sh

FILENAME="$1"
BIN="$2"

export PATH="$BIN:$PATH"
chmod +x "$BIN/solc"

mkdir /results
java -Xmx16G -jar /securify_jar/securify.jar --output /results.json -fs "$FILENAME"
