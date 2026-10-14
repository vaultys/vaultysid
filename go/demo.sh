#!/bin/bash

# VaultysID CLI Demonstration Script
# This script demonstrates the key features of the VaultysID CLI.
# Secrets are kept in 0600 files and passed with --secret-file, never on argv.

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if CLI is built
if [ ! -f "./vaultysid-cli" ]; then
    echo -e "${YELLOW}Building VaultysID CLI...${NC}"
    go build -o vaultysid-cli ./cmd/vaultysid-cli
fi

json_field() { grep -o "\"$1\": *\"[^\"]*" | sed 's/.*"\([^"]*\)$/\1/'; }

echo -e "${BLUE}=====================================${NC}"
echo -e "${BLUE}  VaultysID CLI Demonstration${NC}"
echo -e "${BLUE}=====================================${NC}"
echo

# Demo directory (git-ignored)
DEMO_DIR="demo_output"
rm -rf "$DEMO_DIR"
mkdir -p "$DEMO_DIR"
chmod 700 "$DEMO_DIR"

PERSON_SECRET_FILE="$DEMO_DIR/person.secret"
MACHINE_SECRET_FILE="$DEMO_DIR/machine.secret"
PW_FILE="$DEMO_DIR/backup.password"
(umask 077; echo "demo backup password" > "$PW_FILE")

# Step 1: Generate identities
echo -e "${GREEN}Step 1: Generating Identities${NC}"
./vaultysid-cli generate person --out "$PERSON_SECRET_FILE" > "$DEMO_DIR/person.json"
PERSON_ID=$(json_field id < "$DEMO_DIR/person.json")
PERSON_DID=$(json_field did < "$DEMO_DIR/person.json")
echo "Person DID: $PERSON_DID"

./vaultysid-cli generate machine --out "$MACHINE_SECRET_FILE" > "$DEMO_DIR/machine.json"
MACHINE_ID=$(json_field id < "$DEMO_DIR/machine.json")
MACHINE_DID=$(json_field did < "$DEMO_DIR/machine.json")
echo "Machine DID: $MACHINE_DID"
echo

S="--secret-file $PERSON_SECRET_FILE"

# Step 2-5: IDManager
echo -e "${GREEN}Step 2: Initializing IDManager${NC}"
./vaultysid-cli manager init "$DEMO_DIR/person.store" $S
echo

echo -e "${GREEN}Step 3: Setting Personal Information${NC}"
./vaultysid-cli manager set-name "$DEMO_DIR/person.store" "Alice Demo" $S
./vaultysid-cli manager set-email "$DEMO_DIR/person.store" "alice@demo.example" $S
./vaultysid-cli manager set-phone "$DEMO_DIR/person.store" "+1-555-0100" $S
echo

echo -e "${GREEN}Step 4: Saving Contacts${NC}"
./vaultysid-cli -e hex manager save-app "$DEMO_DIR/person.store" "demo-machine" "$MACHINE_ID" $S
echo

echo -e "${GREEN}Step 5: Listing Apps${NC}"
./vaultysid-cli manager apps "$DEMO_DIR/person.store" $S
echo

# Step 6-7: Document signing
echo -e "${GREEN}Step 6: Document Signing${NC}"
echo "This is an important document that needs to be signed." > "$DEMO_DIR/document.txt"
./vaultysid-cli sign file "$DEMO_DIR/document.txt" $S > "$DEMO_DIR/signature.json"
SIGNATURE=$(json_field signature < "$DEMO_DIR/signature.json")
CHALLENGE=$(json_field challenge < "$DEMO_DIR/signature.json")
echo "Signature: ${SIGNATURE:0:32}..."
echo

echo -e "${GREEN}Step 7: Verifying Signature${NC}"
if ./vaultysid-cli verify file "$PERSON_ID" "$DEMO_DIR/document.txt" "$SIGNATURE" --challenge "$CHALLENGE" | grep -q '"valid": true'; then
    echo -e "${GREEN}✓ Signature verified successfully${NC}"
else
    echo -e "${RED}✗ Signature verification failed${NC}"
fi
echo

# Step 8: Encryption
echo -e "${GREEN}Step 8: File Encryption/Decryption${NC}"
echo "This is sensitive information that should be encrypted." > "$DEMO_DIR/sensitive.txt"
./vaultysid-cli encrypt "$DEMO_DIR/sensitive.txt" --out "$DEMO_DIR/sensitive.enc" $S
./vaultysid-cli decrypt "$DEMO_DIR/sensitive.enc" --out "$DEMO_DIR/sensitive.dec" $S
if cmp -s "$DEMO_DIR/sensitive.txt" "$DEMO_DIR/sensitive.dec"; then
    echo -e "${GREEN}✓ Decrypted file matches original${NC}"
else
    echo -e "${RED}✗ Files do not match${NC}"
fi
echo

# Step 9: HMAC
echo -e "${GREEN}Step 9: HMAC Computation${NC}"
HMAC=$(./vaultysid-cli hmac "test data" $S | json_field hmac)
echo "HMAC of 'test data': ${HMAC:0:32}..."
echo

# Step 10: Backup
echo -e "${GREEN}Step 10: Backup Export/Import${NC}"
./vaultysid-cli manager export "$DEMO_DIR/person.store" --out "$DEMO_DIR/backup.b64" --password-file "$PW_FILE" $S
./vaultysid-cli manager import "$DEMO_DIR/person_restored.store" "@$DEMO_DIR/backup.b64" --password-file "$PW_FILE" $S
./vaultysid-cli manager apps "$DEMO_DIR/person_restored.store" $S
echo

# Step 11: Challenge signing
echo -e "${GREEN}Step 11: Challenge-Response Authentication${NC}"
CHAL=$(echo -n "challenge-$(date +%s)" | xxd -p | tr -d '\n')
CHALLENGE_SIG=$(./vaultysid-cli sign challenge "$CHAL" $S | json_field signature)
if ./vaultysid-cli verify challenge "$PERSON_ID" "$CHAL" "$CHALLENGE_SIG" | grep -q '"valid": true'; then
    echo -e "${GREEN}✓ Challenge verified successfully - Authentication OK${NC}"
else
    echo -e "${RED}✗ Challenge verification failed${NC}"
fi
echo

echo -e "${BLUE}=====================================${NC}"
echo -e "${BLUE}  Demo Complete!${NC}"
echo -e "${BLUE}=====================================${NC}"
echo "Person DID: $PERSON_DID"
echo "Machine DID: $MACHINE_DID"
