#!/bin/bash
set -e

echo "=== VaultysID CLI Demo ==="
echo

# Generate a person identity
echo "1. Generating person identity..."
./vaultysid-cli generate person -o json > person.json
SECRET=$(cat ./person.json | jq -r .secret)
ID=$(cat ./person.json | jq -r .id)
echo "Generated identity with ID: ${ID}"
echo "secret: ${SECRET}"
echo

# Sign some data
echo "2. Signing data..."
DATA=$(echo -n "Hello, VaultysID!" | base64)
echo "data to sign: ${DATA}"
SIG=$(./vaultysid-cli sign data "$SECRET" "$DATA" -o json | jq -r .signature)
echo "Signature: ${SIG}"
echo

# Verify signature
echo "3. Verifying signature..."
RESULT=$(./vaultysid-cli verify data $ID $DATA $SIG -o json)
echo "Verification result: $RESULT"
echo

echo "Demo complete!"
