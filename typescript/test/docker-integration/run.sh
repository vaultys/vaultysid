#!/usr/bin/env bash
# ── VaultysID Docker Integration Test Runner ──
#
# Usage:
#   ./test/docker-integration/run.sh              # run all 3 scenarios
#   ./test/docker-integration/run.sh happy         # run only the happy-path scenario
#   ./test/docker-integration/run.sh denied        # run only the denied-capability scenario
#   ./test/docker-integration/run.sh multi         # run only the multi-agent scenario
#   ./test/docker-integration/run.sh local         # run happy-path locally without Docker

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
PROJECT_NAME="vaultysid-integ"
TIMEOUT=120  # seconds

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log()  { echo -e "${YELLOW}▶ $1${NC}"; }
pass() { echo -e "${GREEN}✅ $1${NC}"; }
fail() { echo -e "${RED}❌ $1${NC}"; }

cleanup() {
  log "Cleaning up containers…"
  docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" down --remove-orphans --timeout 5 2>/dev/null || true
}

# ── Run a specific profile (set of services) ──
run_scenario() {
  local name="$1"
  shift
  local services=("$@")

  log "Running scenario: $name"
  log "Services: ${services[*]}"

  # Build & run with timeout
  if timeout "$TIMEOUT" docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" \
      up --build --abort-on-container-exit "${services[@]}" 2>&1; then
    pass "$name scenario PASSED"
    return 0
  else
    local exit_code=$?
    if [ "$exit_code" -eq 124 ]; then
      fail "$name scenario TIMED OUT after ${TIMEOUT}s"
    else
      fail "$name scenario FAILED (exit $exit_code)"
    fi
    return 1
  fi
}

# ── Local mode (no Docker) ──
run_local() {
  local scenario="${1:-all}"
  local failures=0
  cd "$SCRIPT_DIR/../.."

  if [[ "$scenario" == "all" || "$scenario" == "happy" ]]; then
    log "Running happy-path scenario locally…"
    BROKER_PORT=19000 BROKER_NAME=local-broker pnpm tsx test/docker-integration/broker.ts &
    local broker_pid=$!
    sleep 2
    BROKER_HOST=127.0.0.1 BROKER_PORT=19000 AGENT_NAME=local-agent pnpm tsx test/docker-integration/agent.ts
    local agent_exit=$?
    wait "$broker_pid" 2>/dev/null || true
    if [ "$agent_exit" -eq 0 ]; then pass "Local happy-path PASSED"; else fail "Local happy-path FAILED"; failures=$((failures + 1)); fi
  fi

  if [[ "$scenario" == "all" || "$scenario" == "denied" ]]; then
    log "Running denied scenario locally…"
    BROKER_PORT=19010 BROKER_NAME=local-denied-broker pnpm tsx test/docker-integration/denied-broker.ts &
    local denied_broker_pid=$!
    sleep 2
    BROKER_HOST=127.0.0.1 BROKER_PORT=19010 AGENT_NAME=local-denied-agent pnpm tsx test/docker-integration/denied-agent.ts
    local denied_exit=$?
    wait "$denied_broker_pid" 2>/dev/null || true
    if [ "$denied_exit" -eq 0 ]; then pass "Local denied-capability PASSED"; else fail "Local denied-capability FAILED"; failures=$((failures + 1)); fi
  fi

  if [[ "$scenario" == "all" || "$scenario" == "multi" ]]; then
    log "Running multi-agent scenario locally…"
    BROKER_PORT=19020 BROKER_NAME=local-multi-broker AGENT_COUNT=2 pnpm tsx test/docker-integration/multi-broker.ts &
    local multi_broker_pid=$!
    sleep 2
    BROKER_HOST=127.0.0.1 BROKER_PORT=19020 AGENT_NAME=local-multi-agent-0 AGENT_INDEX=0 pnpm tsx test/docker-integration/multi-agent.ts &
    local multi0_pid=$!
    sleep 1
    BROKER_HOST=127.0.0.1 BROKER_PORT=19020 AGENT_NAME=local-multi-agent-1 AGENT_INDEX=1 pnpm tsx test/docker-integration/multi-agent.ts &
    local multi1_pid=$!
    wait "$multi0_pid" 2>/dev/null; local m0_exit=$?
    wait "$multi1_pid" 2>/dev/null; local m1_exit=$?
    wait "$multi_broker_pid" 2>/dev/null || true
    if [ "$m0_exit" -eq 0 ] && [ "$m1_exit" -eq 0 ]; then pass "Local multi-agent PASSED"; else fail "Local multi-agent FAILED (agent0=$m0_exit, agent1=$m1_exit)"; failures=$((failures + 1)); fi
  fi

  return $failures
}

# ── Main ──
main() {
  local scenario="${1:-all}"
  local failures=0

  # Ensure we clean up on exit
  trap cleanup EXIT

  case "$scenario" in
    local)
      run_local || failures=$((failures + 1))
      ;;
    happy)
      cleanup
      run_scenario "happy-path" broker agent || failures=$((failures + 1))
      ;;
    denied)
      cleanup
      run_scenario "denied-capability" denied-broker denied-agent || failures=$((failures + 1))
      ;;
    multi)
      cleanup
      run_scenario "multi-agent" multi-broker multi-agent-0 multi-agent-1 || failures=$((failures + 1))
      ;;
    all)
      cleanup

      run_scenario "happy-path" broker agent || failures=$((failures + 1))
      cleanup

      run_scenario "denied-capability" denied-broker denied-agent || failures=$((failures + 1))
      cleanup

      run_scenario "multi-agent" multi-broker multi-agent-0 multi-agent-1 || failures=$((failures + 1))
      cleanup
      ;;
    *)
      echo "Usage: $0 [all|happy|denied|multi|local]"
      exit 1
      ;;
  esac

  echo ""
  if [ "$failures" -gt 0 ]; then
    fail "$failures scenario(s) failed"
    exit 1
  else
    pass "All integration scenarios passed!"
    exit 0
  fi
}

main "$@"
