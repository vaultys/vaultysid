#!/bin/bash

# Comprehensive Interoperability Test Suite for VaultysId
# Tests Ed25519 and Dilithium algorithms across TypeScript and Rust implementations

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║        VaultysId Comprehensive Interoperability Test Suite         ║${NC}"
echo -e "${BLUE}║              Testing Ed25519 and Dilithium Algorithms              ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════════╝${NC}\n"

# Track test results
TESTS_PASSED=0
TESTS_FAILED=0
FAILED_TESTS=""

# Function to run a test and track results
run_test() {
    local test_name="$1"
    local test_command="$2"

    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}Running: ${test_name}${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

    if eval "$test_command"; then
        echo -e "\n${GREEN}✅ ${test_name} PASSED${NC}\n"
        ((TESTS_PASSED++))
    else
        echo -e "\n${RED}❌ ${test_name} FAILED${NC}\n"
        ((TESTS_FAILED++))
        FAILED_TESTS="${FAILED_TESTS}\n  - ${test_name}"
    fi
    return 0
}

# Clean up any previous test artifacts
echo -e "${YELLOW}Cleaning up previous test artifacts...${NC}"
rm -rf typescript/test/interops/tmp/*
rm -rf typescript/test/interops/compatibility-data
mkdir -p typescript/test/interops/tmp
echo -e "${GREEN}✓ Cleanup complete${NC}\n"

# Part 1: Generate TypeScript Test Data
echo -e "${MAGENTA}═══════════════════════════════════════════════════════════════════════${NC}"
echo -e "${MAGENTA}Part 1: Generating TypeScript Test Data (Ed25519 & Dilithium)${NC}"
echo -e "${MAGENTA}═══════════════════════════════════════════════════════════════════════${NC}\n"

run_test "TypeScript Test Data Generation" \
    "cd typescript && pnpx ts-node ./test/interops/compatibility-export.ts"

# Part 2: Rust Compatibility Tests
echo -e "${MAGENTA}═══════════════════════════════════════════════════════════════════════${NC}"
echo -e "${MAGENTA}Part 2: Rust Compatibility Tests${NC}"
echo -e "${MAGENTA}═══════════════════════════════════════════════════════════════════════${NC}\n"

# Ed25519 Tests
run_test "" \
    "cd ../rust && cargo test --test typescript_compatibility  -- | grep -q ' 0 failed'"
# Part 3: Cross-Language Protocol Tests
echo -e "${MAGENTA}═══════════════════════════════════════════════════════════════════════${NC}"
echo -e "${MAGENTA}Part 3: Cross-Language Protocol Tests${NC}"
echo -e "${MAGENTA}═══════════════════════════════════════════════════════════════════════${NC}\n"

cd ..

# Function to run cross-language test
run_cross_language_test() {
    local mode="$1"
    local channel="test-channel-$$-$RANDOM"
    ./interops/run-cross-language-test.sh "$mode" "$channel" 2>&1 | tee /tmp/cross-lang-test.log
    grep -q "Test completed successfully" /tmp/cross-lang-test.log
}

run_test "Ed25519: TypeScript accepts ↔ Rust asks" \
    "run_cross_language_test default"

run_test "Ed25519: Rust accepts ↔ TypeScript asks" \
    "run_cross_language_test reverse"

run_test "Dilithium: TypeScript accepts ↔ Rust asks" \
    "run_cross_language_test dilithium"

run_test "Mixed: Ed25519 accepts ↔ Dilithium asks" \
    "run_cross_language_test mixed"

# Part 4: Performance Comparison
echo -e "${MAGENTA}═══════════════════════════════════════════════════════════════════════${NC}"
echo -e "${MAGENTA}Part 4: Performance Comparison${NC}"
echo -e "${MAGENTA}═══════════════════════════════════════════════════════════════════════${NC}\n"

echo -e "${YELLOW}Running performance benchmarks...${NC}"

# Run Rust performance test
echo -e "${CYAN}Rust Performance Test:${NC}"
pwd
cd ./rust && cargo test --test dilithium_integration_test test_dilithium_performance_comparison -- --nocapture 2>&1 | grep -E "(generation time|signing time|verification time)" || true
cd ..

# Run TypeScript performance test (if available)
if [ -f "typescript/test/interops/performance-test.ts" ]; then
    echo -e "${CYAN}TypeScript Performance Test:${NC}"
    cd typescript && pnpx ts-node test/interops/performance-test.ts || true
    cd ..
fi

# Part 5: Test Summary
echo -e "\n${MAGENTA}═══════════════════════════════════════════════════════════════════════${NC}"
echo -e "${MAGENTA}Test Summary${NC}"
echo -e "${MAGENTA}═══════════════════════════════════════════════════════════════════════${NC}\n"

TOTAL_TESTS=$((TESTS_PASSED + TESTS_FAILED))

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                    ALL TESTS PASSED! 🎉                             ${NC}"
    echo -e "${GREEN}║                                                                     ${NC}"
    echo -e "${GREEN}║  Total Tests: ${TOTAL_TESTS}                                        ${NC}"
    echo -e "${GREEN}║  ✅ Passed: ${TESTS_PASSED}                                         ${NC}"
    echo -e "${GREEN}║  ❌ Failed: ${TESTS_FAILED}                                          ${NC}"
    echo -e "${GREEN}║                                                                     ${NC}"
    echo -e "${GREEN}║  Both Ed25519 and Dilithium algorithms are fully compatible         ${NC}"
    echo -e "${GREEN}║  between TypeScript and Rust implementations!                       ${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════════════╝${NC}"
else
    echo -e "${RED}╔════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║                    SOME TESTS FAILED ⚠️                             ${NC}"
    echo -e "${RED}║                                                                     ${NC}"
    echo -e "${RED}║  Total Tests: ${TOTAL_TESTS}                                        ${NC}"
    echo -e "${RED}║  ✅ Passed: ${TESTS_PASSED}                                         ${NC}"
    echo -e "${RED}║  ❌ Failed: ${TESTS_FAILED}                                          ${NC}"
    echo -e "${RED}║                                                                     ${NC}"
    echo -e "${RED}║  Failed Tests:${FAILED_TESTS}                                       ${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════════════════════╝${NC}"
    exit 1
fi

# Clean up temporary files
rm -f /tmp/cross-lang-test.log

echo -e "\n${CYAN}Test suite completed successfully!${NC}"
echo -e "${CYAN}Both Ed25519 and Dilithium (post-quantum) algorithms are working correctly.${NC}\n"
