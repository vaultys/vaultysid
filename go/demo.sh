#!/bin/bash

# VaultysID CLI Demonstration Script
# This script demonstrates the key features of the VaultysID CLI

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

echo -e "${BLUE}=====================================${NC}"
echo -e "${BLUE}  VaultysID CLI Demonstration${NC}"
echo -e "${BLUE}=====================================${NC}"
echo

# Create temp directory for demo files
DEMO_DIR="demo_output"
mkdir -p $DEMO_DIR

# Step 1: Generate identities
echo -e "${GREEN}Step 1: Generating Identities${NC}"
echo "Generating a person identity..."
./vaultysid-cli generate person -o json > $DEMO_DIR/person.json
PERSON_SECRET=$(cat $DEMO_DIR/person.json | grep -o '"secret":"[^"]*' | cut -d'"' -f4)
PERSON_ID=$(cat $DEMO_DIR/person.json | grep -o '"id":"[^"]*' | cut -d'"' -f4)
PERSON_DID=$(cat $DEMO_DIR/person.json | grep -o '"did":"[^"]*' | cut -d'"' -f4)
echo "Person DID: $PERSON_DID"
echo

echo "Generating a machine identity..."
./vaultysid-cli generate machine -o json > $DEMO_DIR/machine.json
MACHINE_SECRET=$(cat $DEMO_DIR/machine.json | grep -o '"secret":"[^"]*' | cut -d'"' -f4)
MACHINE_ID=$(cat $DEMO_DIR/machine.json | grep -o '"id":"[^"]*' | cut -d'"' -f4)
MACHINE_DID=$(cat $DEMO_DIR/machine.json | grep -o '"did":"[^"]*' | cut -d'"' -f4)
echo "Machine DID: $MACHINE_DID"
echo

# Step 2: Initialize IDManager
echo -e "${GREEN}Step 2: Initializing IDManager${NC}"
echo "Creating identity store for person..."
./vaultysid-cli manager init "$PERSON_SECRET" $DEMO_DIR/person.store
echo

# Step 3: Set personal information
echo -e "${GREEN}Step 3: Setting Personal Information${NC}"
./vaultysid-cli manager set-name "$PERSON_SECRET" $DEMO_DIR/person.store "Alice Demo"
./vaultysid-cli manager set-email "$PERSON_SECRET" $DEMO_DIR/person.store "alice@demo.example"
./vaultysid-cli manager set-phone "$PERSON_SECRET" $DEMO_DIR/person.store "+1-555-0100"
echo "Personal information set successfully"
echo

# Step 4: Save contacts
echo -e "${GREEN}Step 4: Saving Contacts${NC}"
./vaultysid-cli manager save-contact "$PERSON_SECRET" $DEMO_DIR/person.store "$MACHINE_ID" \
    name="Demo Machine" type="machine" purpose="testing"
echo "Contact saved successfully"
echo

# Step 5: List contacts
echo -e "${GREEN}Step 5: Listing Contacts${NC}"
./vaultysid-cli manager contacts "$PERSON_SECRET" $DEMO_DIR/person.store
echo

# Step 6: Create and sign a document
echo -e "${GREEN}Step 6: Document Signing${NC}"
echo "Creating a test document..."
echo "This is an important document that needs to be signed." > $DEMO_DIR/document.txt
echo "Content: $(cat $DEMO_DIR/document.txt)"
echo

echo "Signing the document..."
SIGNATURE=$(./vaultysid-cli sign file "$PERSON_SECRET" $DEMO_DIR/document.txt -o json | grep -o '"signature":"[^"]*' | cut -d'"' -f4)
echo "Signature: ${SIGNATURE:0:32}..."
echo

# Step 7: Verify signature
echo -e "${GREEN}Step 7: Verifying Signature${NC}"
./vaultysid-cli verify file "$PERSON_ID" $DEMO_DIR/document.txt "$SIGNATURE" -o json > $DEMO_DIR/verify_result.json
VALID=$(cat $DEMO_DIR/verify_result.json | grep -o '"valid":[^,}]*' | cut -d':' -f2)
if [ "$VALID" = "true" ]; then
    echo -e "${GREEN}✓ Signature verified successfully${NC}"
else
    echo -e "${RED}✗ Signature verification failed${NC}"
fi
echo

# Step 8: Encrypt and decrypt data
echo -e "${GREEN}Step 8: File Encryption/Decryption${NC}"
echo "Creating sensitive data..."
echo "This is sensitive information that should be encrypted." > $DEMO_DIR/sensitive.txt
echo

echo "Encrypting file..."
./vaultysid-cli encrypt "$PERSON_SECRET" $DEMO_DIR/sensitive.txt $DEMO_DIR/sensitive.enc
echo "File encrypted successfully"
echo

echo "Decrypting file..."
./vaultysid-cli decrypt "$PERSON_SECRET" $DEMO_DIR/sensitive.enc $DEMO_DIR/sensitive.dec
echo "File decrypted successfully"
echo

echo "Comparing original and decrypted files..."
if cmp -s $DEMO_DIR/sensitive.txt $DEMO_DIR/sensitive.dec; then
    echo -e "${GREEN}✓ Decrypted file matches original${NC}"
else
    echo -e "${RED}✗ Files do not match${NC}"
fi
echo

# Step 9: HMAC computation
echo -e "${GREEN}Step 9: HMAC Computation${NC}"
TEST_DATA=$(echo -n "test data" | base64)
HMAC=$(./vaultysid-cli hmac "$PERSON_SECRET" "$TEST_DATA" -o json | grep -o '"hmac":"[^"]*' | cut -d'"' -f4)
echo "HMAC of 'test data': ${HMAC:0:32}..."
echo

# Step 10: Export and import backup
echo -e "${GREEN}Step 10: Backup Export/Import${NC}"
echo "Exporting identity manager data..."
./vaultysid-cli manager export "$PERSON_SECRET" $DEMO_DIR/person.store > $DEMO_DIR/backup.b64
echo "Backup exported successfully"
echo

echo "Creating new store and importing backup..."
./vaultysid-cli manager init "$PERSON_SECRET" $DEMO_DIR/person_restored.store
BACKUP_DATA=$(cat $DEMO_DIR/backup.b64)
./vaultysid-cli manager import "$PERSON_SECRET" $DEMO_DIR/person_restored.store "$BACKUP_DATA"
echo "Backup imported successfully"
echo

echo "Verifying restored contacts..."
./vaultysid-cli manager contacts "$PERSON_SECRET" $DEMO_DIR/person_restored.store
echo

# Step 11: Challenge signing (authentication)
echo -e "${GREEN}Step 11: Challenge-Response Authentication${NC}"
echo "Creating authentication challenge..."
CHALLENGE=$(echo -n "challenge-$(date +%s)" | base64)
echo "Challenge: $CHALLENGE"
echo

echo "Signing challenge..."
CHALLENGE_SIG=$(./vaultysid-cli sign challenge "$PERSON_SECRET" "$CHALLENGE" -o json | grep -o '"signature":"[^"]*' | cut -d'"' -f4)
echo "Challenge signature: ${CHALLENGE_SIG:0:32}..."
echo

echo "Verifying challenge signature..."
./vaultysid-cli verify challenge "$PERSON_ID" "$CHALLENGE" "$CHALLENGE_SIG" -o json > $DEMO_DIR/challenge_verify.json
CHALLENGE_VALID=$(cat $DEMO_DIR/challenge_verify.json | grep -o '"valid":[^,}]*' | cut -d':' -f2)
if [ "$CHALLENGE_VALID" = "true" ]; then
    echo -e "${GREEN}✓ Challenge verified successfully - Authentication OK${NC}"
else
    echo -e "${RED}✗ Challenge verification failed${NC}"
fi
echo

# Summary
echo -e "${BLUE}=====================================${NC}"
echo -e "${BLUE}  Demo Complete!${NC}"
echo -e "${BLUE}=====================================${NC}"
echo
echo "Generated files in $DEMO_DIR/:"
ls -la $DEMO_DIR/
echo
echo -e "${GREEN}Key Takeaways:${NC}"
echo "1. Generated decentralized identities for person and machine"
echo "2. Managed identity data with IDManager"
echo "3. Signed and verified documents"
echo "4. Encrypted and decrypted sensitive files"
echo "5. Performed challenge-response authentication"
echo "6. Exported and imported identity backups"
echo
echo "Person DID: $PERSON_DID"
echo "Machine DID: $MACHINE_DID"
