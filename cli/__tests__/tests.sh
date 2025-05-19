#!/bin/bash

# Function to print logs in green (works on macOS and other Unix-like systems)
result() {
    printf "\033[0;32m%s\033[0m\n" "$1"
}

# Add the directory containing vaultysid-cli to PATH
SCRIPT_DIR="$( pwd )/bin"
export PATH="$SCRIPT_DIR/..:$PATH"
if [ -f "$SCRIPT_DIR/vaultysid-cli" ]; then
    VAULTYSID_CLI="$SCRIPT_DIR/vaultysid-cli"
# Check in the parent directory
elif [ -f "$SCRIPT_DIR/../vaultysid-cli" ]; then
    VAULTYSID_CLI="$SCRIPT_DIR/../vaultysid-cli"
# Check in the PATH
elif command -v vaultysid-cli >/dev/null 2>&1; then
    VAULTYSID_CLI="vaultysid-cli"
else
    echo "Error: vaultysid-cli not found"
    exit 1
fi

echo "vaultysid-cli generate"
secret1=$("$VAULTYSID_CLI" generate)
result "$secret1"

echo "vaultysid-cli generate"
secret2=$("$VAULTYSID_CLI" generate)
result "$secret2"

echo "vaultysid-cli generate"
secret3=$("$VAULTYSID_CLI" generate)
result "$secret3"

echo "vaultysid-cli fromSecret $secret1 --display id"
id1=$("$VAULTYSID_CLI" fromSecret "$secret1" --display id)
result "$id1"

echo "vaultysid-cli fromSecret $secret1 --display did"
result "$("$VAULTYSID_CLI" fromSecret "$secret1" --display did)"

echo "vaultysid-cli fromSecret $secret1 --display fingerprint"
result "$("$VAULTYSID_CLI" fromSecret "$secret1" --display fingerprint)"

echo "vaultysid-cli fromSecret $secret2 --display id"
id2=$("$VAULTYSID_CLI" fromSecret "$secret2" --display id)
result "$id2"

echo "vaultysid-cli fromSecret $secret3 --display id"
id3=$("$VAULTYSID_CLI" fromSecret "$secret3" --display id)
result "$id3"

echo "vaultysid-cli encrypt aGVsbG8gd29ybGQ= $id1 $id2"
encrypted=$("$VAULTYSID_CLI" encrypt aGVsbG8gd29ybGQ= "$id1" "$id2")
result "$encrypted"

echo "vaultysid-cli decrypt $encrypted $secret1"
decrypted1=$("$VAULTYSID_CLI" decrypt "$encrypted" "$secret1")
result "$decrypted1"

echo "vaultysid-cli decrypt $encrypted $secret2"
decrypted2=$("$VAULTYSID_CLI" decrypt "$encrypted" "$secret2")
result "$decrypted2"

echo "vaultysid-cli decrypt $encrypted $secret3"
decrypted3=$("$VAULTYSID_CLI" decrypt "$encrypted" "$secret3")
result "$decrypted3"

echo "vaultysid-cli sign aGVsbG8gd29ybGQ= $secret1"
signature=$("$VAULTYSID_CLI" sign aGVsbG8gd29ybGQ= "$secret1")
result "$signature"
