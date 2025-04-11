#!/bin/sh

FILENAME="$1"
BIN="$2"

export PATH="$BIN:$PATH"
chmod +x "$BIN/solc"

mkdir /results

for c in `python3 "$BIN/printContractNames.py" "${FILENAME}"`; do 
        manticore --no-colors --thorough-mode --txlimit 2 --contract "${c}" "${FILENAME#/}"
        mv /mcore_* /results
done
