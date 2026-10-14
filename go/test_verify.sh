#!/bin/bash
set -e

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# Generate identity (secret written to a 0600 file)
ID=$(./vaultysid-cli generate person --out "$WORK/id.secret" -o json | jq -r .id)
echo "Generated identity"
echo "ID: $ID"
echo

# Create data
DATA=$(echo -n "Test message" | xxd -p | tr -d '\n')
echo "Data to sign: $DATA"
echo

# Sign
SIG_JSON=$(./vaultysid-cli sign data "$DATA" --secret-file "$WORK/id.secret" -o json)
echo "Sign result: $SIG_JSON"
SIG=$(echo "$SIG_JSON" | jq -r .signature)
echo

# Verify
VERIFY_JSON=$(./vaultysid-cli verify data "$ID" "$DATA" "$SIG" -o json)
echo "Verify result: $VERIFY_JSON"
