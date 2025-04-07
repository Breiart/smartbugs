#!/bin/sh

FILENAME="$1"
BIN="$2"
MAIN="$3"

export PATH="$BIN:$PATH"
chmod +x "$BIN"/solc

# TODO: FIX THIS SCRIPT


# Extract contract names from the file
CONTRACT="${FILENAME%.sol}"
CONTRACT="${CONTRACT##*/}"
CONTRACTS=$(python3 "$BIN"/printContractNames.py "$FILENAME")

# If MAIN flag is 1, ensure the expected contract exists in the file
if [ "$MAIN" -eq 1 ]; then
    if echo "$CONTRACTS" | grep -q "$CONTRACT"; then
        CONTRACTS="$CONTRACT"
    else
        echo "Contract '$CONTRACT' not found in $FILENAME"
        exit 127
    fi
fi

# Compile the Solidity contract using solc
echo "Compiling $FILENAME..."
SOLC_OUTPUT=$("$BIN"/solc --combined-json abi,bin "$FILENAME")
if [ $? -ne 0 ]; then
    echo "Compilation failed"
    exit 1
fi

# Optionally, write SOLC_OUTPUT to a temporary file if Echidna requires it
TEMP_COMPILE_OUTPUT=$(mktemp)
echo "$SOLC_OUTPUT" > "$TEMP_COMPILE_OUTPUT"

# Run Echidna against the compiled contract
echo "Running Echidna tests on $CONTRACTS..."
echidna "$TEMP_COMPILE_OUTPUT" --contract "$CONTRACTS" # Additional Echidna options can be added here

# Clean up temporary files if needed
rm "$TEMP_COMPILE_OUTPUT"