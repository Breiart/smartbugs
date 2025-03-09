#!/bin/sh

FILENAME="$1"
BIN="$2"
MAIN="$3"
ARGS="$4"  # Prendi dal quarto al sesto parametro

export PATH="$BIN:$PATH"
chmod +x $BIN/solc

CONTRACT="${FILENAME%.sol}"
CONTRACT="${CONTRACT##*/}"
CONTRACTS=$(python3 "$BIN"/printContractNames.py "$FILENAME")

if [ "$MAIN" -eq 1 ]; then
    if (echo "$CONTRACTS" | grep -q "$CONTRACT"); then
        CONTRACTS="$CONTRACT"
    else
        echo "Contract '$CONTRACT' not found in $FILENAME"
        exit 127
    fi
fi

cd /MAIAN/tool

for CONTRACT in $CONTRACTS; do
    if echo "$ARGS" | grep -q "\-s"; then
        python3 maian.py -c 0 -s "$FILENAME" "$CONTRACT"
    fi
    if echo "$ARGS" | grep -q "\-g"; then
        python3 maian.py -c 2 -s "$FILENAME" "$CONTRACT"
    fi
    if echo "$ARGS" | grep -q "\-p"; then
        python3 maian.py -c 1 -s "$FILENAME" "$CONTRACT"
    fi
done
