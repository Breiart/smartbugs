#!/bin/sh

FILENAME="$1"
BIN="$2"
ARGS="${3:-}"

export PATH="$BIN:$PATH"
chmod +x "$BIN/solc"

mkdir /results

for c in `python3 "$BIN/printContractNames.py" "${FILENAME}"`; do 
        if [ -n "$ARGS" ]; then
            manticore --no-colors --contract "${c}" "${FILENAME#/}" $ARGS
        else
            manticore --no-colors --contract "${c}" "${FILENAME#/}"
        fi
        mv /mcore_* /results
done
