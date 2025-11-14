#!/bin/bash

# Cross-Language IdManager Protocol Test Runner
# This script runs TypeScript acceptContact and Rust askContact together

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     TypeScript-Rust IdManager Cross-Language Test          ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}\n"


# Parse command line arguments
MODE=${1:-"default"}
CHANNEL_NAME=${2:-"test-channel-$$"}

# Clean up channel directory
CHANNEL_DIR="test/interops/tmp/channels/$CHANNEL_NAME"
rm -rf "$CHANNEL_DIR"
mkdir -p "$CHANNEL_DIR"

echo -e "${CYAN}Test Configuration:${NC}"
echo -e "  Channel: $CHANNEL_NAME"
echo -e "  Channel Path: $CHANNEL_DIR\n"

case "$MODE" in
    "default"|"ts-accept-rust-ask")
        echo -e "${GREEN}Mode: TypeScript accepts, Rust asks${NC}\n"
        echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

        # Start TypeScript acceptor in background
        echo -e "${CYAN}[1/2] Starting TypeScript IdManager (acceptContact)...${NC}"
        cd typescript && pnpx ts-node test/interops/cross-language-channel.ts acceptor "$CHANNEL_NAME" > test/interops/tmp/ts-acceptor.log 2>&1 &
        TS_PID=$!

        # Give TypeScript time to initialize
        sleep 5

        # Start Rust asker
        echo -e "${CYAN}[2/2] Starting Rust IdManager (askContact)...${NC}\n"
        echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

        cd rust && cargo run --bin cross_language_test -- asker "$CHANNEL_NAME" && cd ..
        RUST_EXIT=$?

        # Wait for TypeScript to complete
        wait $TS_PID
        TS_EXIT=$?

        echo -e "\n${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

        # Show TypeScript output
        echo -e "\n${CYAN}TypeScript Output:${NC}"
        cat test/interops/tmp/ts-acceptor.log

        if [ $TS_EXIT -eq 0 ] && [ $RUST_EXIT -eq 0 ]; then
            echo -e "\n${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
            echo -e "${GREEN}║                    TEST PASSED! ✅                        ║${NC}"
            echo -e "${GREEN}║  TypeScript acceptContact ←→ Rust askContact SUCCESS      ║${NC}"
            echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
        else
            echo -e "\n${RED}╔════════════════════════════════════════════════════════════╗${NC}"
            echo -e "${RED}║                    TEST FAILED! ❌                        ║${NC}"
            echo -e "${RED}║     Check the logs above for error details                ║${NC}"
            echo -e "${RED}╚════════════════════════════════════════════════════════════════╝${NC}"
            echo -e "\n${YELLOW}Debug: Channel preserved at $CHANNEL_DIR${NC}"
            exit 1
        fi
        ;;

    "reverse"|"rust-accept-ts-ask")
        echo -e "${GREEN}Mode: Rust accepts, TypeScript asks${NC}\n"
        echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

        # Start Rust acceptor in background
        echo -e "${CYAN}[1/2] Starting Rust IdManager (acceptContact)...${NC}"
        cd rust && cargo run --bin cross_language_test -- acceptor "$CHANNEL_NAME" > ../test/interops/tmp/rust-acceptor.log 2>&1 &
        RUST_PID=$!

        # Give Rust time to initialize
        sleep 3

        # Start TypeScript asker
        echo -e "${CYAN}[2/2] Starting TypeScript IdManager (askContact)...${NC}\n"
        echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

        cd typescript && pnpx ts-node test/interops/cross-language-channel.ts asker "$CHANNEL_NAME"
        TS_EXIT=$?

        # Wait for Rust to complete
        wait $RUST_PID
        RUST_EXIT=$?

        echo -e "\n${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

        # Show Rust output
        echo -e "\n${CYAN}Rust Output:${NC}"
        cat test/interops/tmp/rust-acceptor.log

        if [ $TS_EXIT -eq 0 ] && [ $RUST_EXIT -eq 0 ]; then
            echo -e "\n${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
            echo -e "${GREEN}║                    TEST PASSED! ✅                         ║${NC}"
            echo -e "${GREEN}║  Rust acceptContact ←→ TypeScript askContact SUCCESS       ║${NC}"
            echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
        else
            echo -e "\n${RED}╔════════════════════════════════════════════════════════════╗${NC}"
            echo -e "${RED}║                    TEST FAILED! ❌                          ║${NC}"
            echo -e "${RED}║     Check the logs above for error details                 ║${NC}"
            echo -e "${RED}╚════════════════════════════════════════════════════════════════╝${NC}"
            echo -e "\n${YELLOW}Debug: Channel preserved at $CHANNEL_DIR${NC}"
            exit 1
        fi
        ;;

    "manual")
        echo -e "${GREEN}Manual mode - run the commands in separate terminals:${NC}\n"
        echo -e "${YELLOW}Terminal 1 (TypeScript acceptor):${NC}"
        echo -e "  pnpm ts-node test/interops/cross-language-channel.ts acceptor $CHANNEL_NAME\n"
        echo -e "${YELLOW}Terminal 2 (Rust asker):${NC}"
        echo -e "  cd rust && cargo run --bin cross_language_test -- asker $CHANNEL_NAME\n"
        exit 0
        ;;

    *)
        echo -e "${RED}Invalid mode: $MODE${NC}\n"
        echo "Usage: ./run-cross-language-test.sh [mode] [channel-name]"
        echo ""
        echo "Modes:"
        echo "  default    - TypeScript accepts, Rust asks (default)"
        echo "  reverse    - Rust accepts, TypeScript asks"
        echo "  manual     - Show commands for manual testing"
        echo ""
        echo "Example:"
        echo "  ./run-cross-language-test.sh"
        echo "  ./run-cross-language-test.sh reverse"
        echo "  ./run-cross-language-test.sh default my-channel"
        exit 1
        ;;
esac

# Clean up only on success
if [ $? -eq 0 ]; then
    rm -rf "$CHANNEL_DIR"
    echo -e "\n${CYAN}Test completed. Channel cleaned up.${NC}"
else
    echo -e "\n${YELLOW}Test failed. Channel preserved for debugging at: $CHANNEL_DIR${NC}"
fi
