# VaultysID Execution – Docker Integration Tests

End-to-end tests that spin up isolated processes (locally or in Docker containers), each with its own cryptographic identity, and exercise the full **ExecutionManager** flow over TCP.

---

## Architecture

```
┌──────────────┐        TCP (policy)        ┌──────────────┐
│              │◄──────────────────────────  │              │
│    Broker    │                             │    Agent     │
│  (machine)   │  TCP (execution + receipt)  │  (person)    │
│              │◄──────────────────────────► │              │
└──────────────┘                             └──────────────┘
```

Each process:

1. Generates a **fresh VaultysId** on startup (no pre-shared keys).
2. Communicates over a **length-prefixed TCP channel** (`TcpChannel.ts`), which implements the same `Channel` interface used by MemoryChannel.
3. Follows a **two-phase protocol**:
   - **Phase 1 – Policy exchange**: Broker sends its authority-signed `PolicyBundle` + its serialized VaultysId to the agent.
   - **Phase 2 – Execution**: Agent creates and signs an `ExecutionIntent`, then calls `requestExecution` (SRP handshake + intent submission). Broker verifies signatures, evaluates capabilities against the policy, runs a sandbox callback, and returns a signed receipt.

---

## Scenarios

### 1. Happy Path (`broker.ts` + `agent.ts`)

| Role   | What it does                                                                                                                           |
| ------ | -------------------------------------------------------------------------------------------------------------------------------------- |
| Broker | Signs a policy allowing `proc.exec:[echo,ls,cat]` and `fs.read:**`. Listens on port `P` for policy exchange, then `P+1` for execution. |
| Agent  | Connects, receives the signed policy, verifies its signature, creates an intent requesting `proc.exec:echo`, submits it via SRP.       |

**Pass condition**: Agent receives a valid signed receipt with `exit_code: 0`.

### 2. Denied Capability (`denied-broker.ts` + `denied-agent.ts`)

| Role   | What it does                                                                           |
| ------ | -------------------------------------------------------------------------------------- |
| Broker | Same policy as happy path. Expects the intent to be **denied** during evaluation.      |
| Agent  | Requests `fs.delete:/important-data` — a capability not present in the allowed scopes. |

**Pass condition**: Broker throws "Intent denied by policy" and the agent receives a null/error response. Both processes exit 0.

### 3. Multi-Agent (`multi-broker.ts` + `multi-agent.ts` × 2)

| Role   | What it does                                                                                                                                                                            |
| ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Broker | Serves `N` agents sequentially: `N` policy exchanges on port `P`, then `N` execution rounds on port `P+1`.                                                                              |
| Agents | Staggered by `AGENT_INDEX × 3s` to serialize connections to the single-threaded broker. Each agent independently receives the policy, creates its own intent, and gets its own receipt. |

**Pass condition**: All agents get valid receipts. Broker stores `N` receipts.

---

## Files

| File                 | Description                                                                                                                               |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `TcpChannel.ts`      | TCP-based `Channel` implementation with length-prefixed framing. `listen()` accepts exactly one connection then closes the server socket. |
| `broker.ts`          | Happy-path broker process                                                                                                                 |
| `agent.ts`           | Happy-path agent process                                                                                                                  |
| `denied-broker.ts`   | Denied-capability broker process                                                                                                          |
| `denied-agent.ts`    | Denied-capability agent process                                                                                                           |
| `multi-broker.ts`    | Multi-agent broker process                                                                                                                |
| `multi-agent.ts`     | Multi-agent agent process (parameterized by `AGENT_INDEX`)                                                                                |
| `Dockerfile`         | Single image for all roles (Node 22 Alpine + pnpm + tsx)                                                                                  |
| `docker-compose.yml` | Defines all 3 scenarios with isolated networks                                                                                            |
| `run.sh`             | Test runner with local and Docker modes                                                                                                   |

---

## Running

### Local mode (no Docker required)

```bash
# All scenarios
./test/docker-integration/run.sh local

# Individual scenarios
./test/docker-integration/run.sh local happy
./test/docker-integration/run.sh local denied
./test/docker-integration/run.sh local multi
```

Processes run on `127.0.0.1` with offset ports (`19000`, `19010`, `19020`).

### Docker mode

```bash
# All scenarios
./test/docker-integration/run.sh

# Individual scenarios
./test/docker-integration/run.sh happy
./test/docker-integration/run.sh denied
./test/docker-integration/run.sh multi
```

Each scenario runs in an isolated Docker network. The runner builds images, starts containers, waits for completion (120s timeout), and cleans up.

### Direct docker compose

```bash
docker compose -f test/docker-integration/docker-compose.yml up --build --abort-on-container-exit
```

---

## Environment Variables

| Variable      | Used by      | Default   | Description                                   |
| ------------- | ------------ | --------- | --------------------------------------------- |
| `BROKER_HOST` | agents       | `broker`  | Hostname of the broker container              |
| `BROKER_PORT` | all          | `9000`    | Base port (policy on `P`, execution on `P+1`) |
| `BROKER_NAME` | brokers      | `broker`  | Display name in logs                          |
| `AGENT_NAME`  | agents       | `agent`   | Display name in logs                          |
| `AGENT_INDEX` | multi-agent  | `0`       | 0-based index, used to stagger startup        |
| `AGENT_COUNT` | multi-broker | `2`       | Number of agents to expect                    |
| `ALGORITHM`   | all          | `ed25519` | Key algorithm (`ed25519` or `dilithium`)      |

---

## Protocol Flow (Happy Path)

```
    Agent                              Broker
      │                                  │
      │  Phase 1: Policy Exchange        │
      │  ◄─── signed policy + id ────────│  (TCP port P)
      │                                  │
      │  Phase 2: Execution              │
      │  ── SRP handshake ──────────────►│  (TCP port P+1)
      │  ◄── SRP handshake ─────────────│
      │  ── intent + policy ────────────►│
      │                                  │  verify intent sig (agent)
      │                                  │  verify policy sig (authority)
      │                                  │  evaluate caps vs policy
      │                                  │  execute sandbox callback
      │  ◄── signed receipt ─────────────│
      │                                  │
      │  verify receipt sig (broker)     │
      ▼                                  ▼
```

---

## What Gets Tested

- **TcpChannel**: Length-prefixed framing over TCP, single-connection-per-listen semantics
- **Policy signing & verification**: `signPolicy()` / `verifyPolicy()` across process boundaries
- **Intent signing & verification**: `createIntent()` / `verifyIntent()` with SRP mutual authentication
- **Capability evaluation**: `evaluateIntent()` with allowed scopes and denied capabilities
- **Receipt signing & verification**: `signReceipt()` / `verifyReceipt()` end-to-end
- **SRP round-trip**: Full `requestExecution()` / `acceptExecution()` over real network sockets
- **Multi-agent sequencing**: Multiple independent identities interacting with a single broker
- **Policy enforcement**: Requests for uncovered capabilities are correctly rejected
