#!/bin/bash
set -e

echo "=== VaultysID CLI Demo ==="
echo

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# Generate a person identity: the secret goes to a 0600 file, never stdout
echo "1. Generating person identity..."
ID=$(./vaultysid-cli generate person --out "$WORK/person.secret" -o json | jq -r .id)
echo "Generated identity with ID: ${ID}"
echo

# Sign some data
echo "2. Signing data..."
DATA=$(echo -n "Hello, VaultysID!" | xxd -p | tr -d '\n')
echo "data to sign (hex): ${DATA}"
SIG=$(./vaultysid-cli sign data "$DATA" --secret-file "$WORK/person.secret" -o json | jq -r .signature)
echo "Signature: ${SIG}"
echo

# Verify signature
echo "3. Verifying signature..."
RESULT=$(./vaultysid-cli verify data "$ID" "$DATA" "$SIG" -o json)
echo "Verification result: $RESULT"
echo

echo "Demo complete!"
