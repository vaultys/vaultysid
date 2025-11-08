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

# Check if we're in the right directory
if [ ! -f "package.json" ] || [ ! -d "rust" ]; then
    echo -e "${RED}Error: This script must be run from the vaultysid root directory${NC}"
    exit 1
fi

# Parse command line arguments
MODE=${1:-"ts-initiator"}

case "$MODE" in
    "ts-initiator")
        echo -e "${GREEN}Running with TypeScript as initiator (server) and Rust as responder (client)${NC}\n"

        # Kill any existing processes on port 9876
        lsof -ti:9876 | xargs kill -9 2>/dev/null || true

        # Start TypeScript side as initiator (server)
        echo -e "${YELLOW}Starting TypeScript IdManager (Initiator/Server)...${NC}"
        pnpm ts-node ./protocol-interop.ts initiator &
        TS_PID=$!

        # Wait for server to start
        sleep 5

        # Start Rust side as responder (client)
        echo -e "${YELLOW}Starting Rust IdManager (Responder/Client)...${NC}"
        cd rust && cargo run --bin protocol_interop -- responder &
        RUST_PID=$!

        # Wait for both processes to complete
        wait $TS_PID
        TS_EXIT=$?
        wait $RUST_PID
        RUST_EXIT=$?

        if [ $TS_EXIT -eq 0 ] && [ $RUST_EXIT -eq 0 ]; then
            echo -e "\n${GREEN}✅ Test completed successfully!${NC}"
        else
            echo -e "\n${RED}❌ Test failed${NC}"
            exit 1
        fi
        ;;

    "rust-initiator")
        echo -e "${GREEN}Running with Rust as initiator (client) and TypeScript as responder (server)${NC}\n"

        # Kill any existing processes on port 9876
        lsof -ti:9876 | xargs kill -9 2>/dev/null || true

        # Start Rust side as server (responder)
        echo -e "${YELLOW}Starting Rust IdManager (Responder/Server)...${NC}"
        cd rust && cargo run --bin protocol_interop -- responder &
        RUST_PID=$!

        # Wait for server to start
        sleep 5

        # Start TypeScript side as client (initiator)
        echo -e "${YELLOW}Starting TypeScript IdManager (Initiator/Client)...${NC}"
        pnpm ts-node ./protocol-interop.ts initiator &
        TS_PID=$!

        # Wait for both processes to complete
        wait $TS_PID
        TS_EXIT=$?
        wait $RUST_PID
        RUST_EXIT=$?

        if [ $TS_EXIT -eq 0 ] && [ $RUST_EXIT -eq 0 ]; then
            echo -e "\n${GREEN}✅ Test completed successfully!${NC}"
        else
            echo -e "\n${RED}❌ Test failed${NC}"
            exit 1
        fi
        ;;

    "generate-data")
        echo -e "${YELLOW}Generating TypeScript compatibility test data...${NC}"
        npx ts-node ./compatibility-export.ts
        echo -e "${GREEN}✅ Test data generated${NC}"
        ;;

    "run-compat")
        echo -e "${YELLOW}Running compatibility tests...${NC}"

        # First generate TypeScript test data
        echo -e "${BLUE}Step 1: Generating TypeScript test data...${NC}"
        npx ts-node ./compatibility-export.ts

        # Then run Rust compatibility tests
        echo -e "${BLUE}Step 2: Running Rust compatibility tests...${NC}"
        cd rust && cargo test --test typescript_compatibility

        echo -e "${GREEN}✅ All compatibility tests passed${NC}"
        ;;

    *)
        echo -e "${RED}Invalid mode: $MODE${NC}"
        echo
        echo "Usage: ./run-interop-test.sh [mode]"
        echo
        echo "Modes:"
        echo "  ts-initiator   - TypeScript initiates, Rust responds (default)"
        echo "  rust-initiator - Rust initiates, TypeScript responds"
        echo "  generate-data  - Generate TypeScript test data only"
        echo "  run-compat     - Run full compatibility test suite"
        echo
        exit 1
        ;;
esac

echo -e "\n${BLUE}Test completed.${NC}"
