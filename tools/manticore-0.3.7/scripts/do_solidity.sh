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
            #manticore --no-colors --contract "${c}" "${FILENAME#/}"
            manticore \
                --no-colors \
                --contract "${c}" "${FILENAME#/}"\
                --txlimit 1 \
                --evm.ignore_balance EVM.IGNORE_BALANCE \
                --evm.oog ignore \
                --evm.defaultgas 1000000 \
                --smt.timeout 10 \
                --smt.memory 512 \
                --core.timeout 120 \
                --core.procs 1 \
                --avoid-constant \
                --limit-loops \
                
        fi
        mv /mcore_* /results
done
