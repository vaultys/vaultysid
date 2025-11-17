#!/bin/bash

# TypeScript-Rust IdManager Interop Test Runner
# This script coordinates the cross-language protocol test

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔄 TypeScript-Rust IdManager Interop Test${NC}\n"

# Parse command line arguments
MODE=${1:-"run-compat"}

case "$MODE" in
    "generate-data")
        echo -e "${YELLOW}Generating TypeScript compatibility test data...${NC}"
        cd typescript && pnpx ts-node ./test/interops/compatibility-export.ts
        echo -e "${GREEN}✅ Test data generated${NC}"
        ;;

    "run-compat")
        echo -e "${YELLOW}Running compatibility tests...${NC}"

        # First generate TypeScript test data
        echo -e "${BLUE}Step 1: Generating TypeScript test data (Ed25519 & Dilithium)...${NC}"
        cd typescript && pnpx ts-node ./test/interops/compatibility-export.ts

        # Then run Rust compatibility tests
        echo -e "${BLUE}Step 2: Running Rust compatibility tests (Ed25519)...${NC}"
        cd ../rust && cargo test --test typescript_compatibility -- --nocapture test_person_id test_machine_id test_organization_id test_challenge_verification test_ed25519_manager test_deprecated_manager test_diffie_hellman

        echo -e "${BLUE}Step 3: Running Rust compatibility tests (Dilithium)...${NC}"
        cargo test --test typescript_compatibility -- --nocapture test_dilithium_person_id test_dilithium_machine_id test_dilithium_organization_id test_dilithium_signature_verification test_dilithium_manager_direct test_cross_algorithm_diffie_hellman

        echo -e "${GREEN}✅ All compatibility tests passed (Ed25519 & Dilithium)${NC}"
        ;;

    *)
        echo -e "${RED}Invalid mode: $MODE${NC}"
        echo
        echo "Usage: ./run-interop-test.sh [mode]"
        echo
        echo "Modes:"
        echo "  generate-data  - Generate TypeScript test data only (Ed25519 & Dilithium)"
        echo "  run-compat     - Run full compatibility test suite (Ed25519 & Dilithium)"
        echo
        exit 1
        ;;
esac

echo -e "\n${BLUE}Test completed.${NC}"
