#!/bin/sh

FILENAME="$1"
BIN="$2"
MAIN="$3"
ARGS="${4:-0}"  # Prendi dal quarto al sesto parametro

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
    if [ "$ARGS" -ge 0 ] && [ "$ARGS" -le 2 ]; then
        python3 maian.py -s "$FILENAME" "$CONTRACT" -c "$ARGS"
    else
        echo "Invalid argument: $ARGS. Please provide 0, 1, or 2."
        exit 1
    fi
done