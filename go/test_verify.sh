#!/bin/bash
set -e

# Generate identity
JSON=$(./vaultysid-cli generate person -o json)
SECRET=$(echo "$JSON" | jq -r .secret)
ID=$(echo "$JSON" | jq -r .id)
echo "Generated identity"
echo "Secret: $SECRET"
echo "ID: $ID"
echo

# Create data
DATA=$(echo -n "Test message" | base64)
echo "Data to sign: $DATA"
echo

# Sign
SIG_JSON=$(./vaultysid-cli sign data $SECRET $DATA -o json)
echo "Sign result: $SIG_JSON"
SIG=$(echo "$SIG_JSON" | jq -r .signature)
echo "Signature: $SIG"
echo

# Verify
VERIFY_JSON=$(./vaultysid-cli verify data $ID $DATA $SIG -o json)
echo "Verify result: $VERIFY_JSON"
