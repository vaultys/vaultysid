# ExecutionManager – Usage Manual

## Overview

`ExecutionManager` adds a verifiable control layer for AI agent execution on top of VaultysID. It ensures that:

- Every agent is **cryptographically identified** via its VaultysID
- Every execution request is **signed** and **authorized** against a policy
- Policies are **agreed upon via SRP** — mutually authenticated and stored
- Execution results produce a **signed, auditable receipt**
- Agent ↔ Broker communication is **mutually authenticated** via the SRP protocol

There are three roles (two parties can combine roles):

| Role         | Description                                                                |
| ------------ | -------------------------------------------------------------------------- |
| **Producer** | Proposes a policy to an executor via SRP (defines what is allowed)         |
| **Executor** | Accepts policies, creates and signs execution intents                      |
| **Broker**   | Verifies signatures, evaluates policy, delegates execution, signs receipts |

---

## Installation

`ExecutionManager` is part of `@vaultys/id`. No additional packages needed.

```typescript
import { IdManager, VaultysId, MemoryStorage, MemoryChannel, ExecutionManager } from "@vaultys/id";
import type { PolicyBundle, ExecutionIntent, ExecOutcome, SignedReceipt } from "@vaultys/id/src/execution";
```

---

## Quick Start

### 1. Create Identities

Each participant needs a VaultysID backed by an `IdManager`:

```typescript
// Authority (e.g. organization admin)
const authorityId = await VaultysId.generateOrganization();
const authorityStore = MemoryStorage();
const authorityManager = new IdManager(authorityId, authorityStore);
authorityManager.setProtocolVersion(1);

// Agent (e.g. AI model / MCP tool)
const agentId = await VaultysId.generateMachine();
const agentStore = MemoryStorage();
const agentManager = new IdManager(agentId, agentStore);
agentManager.setProtocolVersion(1);

// Broker (e.g. execution gateway)
const brokerId = await VaultysId.generateMachine();
const brokerStore = MemoryStorage();
const brokerManager = new IdManager(brokerId, brokerStore);
brokerManager.setProtocolVersion(1);
```

### 2. Wrap with ExecutionManager

```typescript
const authorityEm = new ExecutionManager(authorityManager);
const agentEm     = new ExecutionManager(agentManager);
const brokerEm    = new ExecutionManager(brokerManager);
```

---

## Policy Bundle

A policy defines what an agent is allowed to do. It is signed by the authority.

### Define a Policy

```typescript
const policy = {
  version: "1.0",
  scopes: {
    "fs.read":         ["/workspace/**"],
    "fs.write":        ["/workspace/**"],
    "scm.net":         ["github.com/myorg/*"],
    "proc.exec.build": ["npm", "cargo"],
    "net.egress.http": ["api.internal.com"],
  },
  denied: [
    "secrets.*",       // all secret operations denied
    "pkg.system",      // no system package installs
    "proc.privilege",  // no privilege escalation
  ],
  constraints: {
    max_runtime: 300,         // seconds
    no_shell_features: true,  // reject argv with |, ;, &, etc.
  },
};
```

### Sign the Policy (Authority)

```typescript
const signedPolicy = await authorityEm.signPolicy(policy);
// signedPolicy now contains a `signature` field
```

### Verify a Policy (Anyone)

```typescript
const isValid = ExecutionManager.verifyPolicy(signedPolicy, authorityManager.vaultysId);
// true if the signature matches the authority's identity
```

---

## SRP Policy Agreement (Recommended)

The preferred way to establish a policy between two parties is via **SRP** (Signing Recognition Protocol). This provides mutual authentication — both parties cryptographically sign the policy agreement, and the result is stored for later verification.

### Flow

1. The **producer** (e.g. an organization admin) proposes a policy via `grantPolicy`
2. The **executor** (e.g. an AI agent) reviews and accepts it via `acceptPolicy`
3. Both sides store the agreed policy + SRP certificate, keyed by the counterpart's DID

The policy content is embedded in the SRP metadata, so it is cryptographically bound to the mutual-authentication certificate.

### Producer Side – Grant a Policy

```typescript
const channel = MemoryChannel.createBidirectionnal();

const counterpart = await producerEm.grantPolicy(
  channel,        // producer's end of the channel
  policy,         // the policy to propose (no signature needed)
);

console.log("Policy agreed with:", counterpart.did);
```

### Executor Side – Accept a Policy

```typescript
const { counterpart, policy } = await executorEm.acceptPolicy(
  channel.otherend!,  // executor's end of the channel
);

console.log("Accepted policy from:", counterpart.did);
console.log("Allowed scopes:", Object.keys(policy.scopes));
```

### Both Sides Together

```typescript
const [counterpart, result] = await Promise.all([
  producerEm.grantPolicy(channel, policy),
  executorEm.acceptPolicy(channel.otherend!),
]);
```

### Reviewing the Policy Before Accepting

The executor can inspect and approve/reject the policy content:

```typescript
const { counterpart, policy } = await executorEm.acceptPolicy(
  channel.otherend!,
  async (policy, producerId) => {
    // Reject if secrets are not denied
    if (!policy.denied.includes("secrets.*")) return false;
    // Reject unknown producers
    if (!trustedDids.includes(producerId.did)) return false;
    return true;
  },
);
```

### Filtering the Counterpart Identity

Both sides accept an optional `accept` callback to filter the peer during SRP:

```typescript
await executorEm.acceptPolicy(
  channel.otherend!,
  undefined,                    // no policy review
  async (producerVaultysId) => {
    // Only accept known producers
    return myManager.getContact(producerVaultysId.did) !== null;
  },
);
```

### Retrieving Stored Policies

After agreement, policies are stored in the `"policies"` substore of the `IdManager`:

```typescript
// By counterpart DID
const stored = executorEm.getPolicy(producerDid);
// stored.policy        → the PolicyBundle
// stored.certificate   → the SRP certificate (mutual-auth proof)
// stored.counterpartDid → the producer's DID
// stored.agreedAt      → timestamp

// All policies
const allPolicies = executorEm.listPolicies();
```

### Verifying a Stored Policy

Re-check that a stored policy's SRP certificate is still valid (both signatures intact):

```typescript
const isValid = await ExecutionManager.verifyStoredPolicy(stored);
```

### What Gets Stored

On both sides, the `"policies"` substore keyed by the counterpart's DID contains:

```typescript
{
  policy: PolicyBundle,    // the agreed policy content
  certificate: Buffer,     // the SRP mutual-auth certificate
  counterpartDid: string,  // the other party's DID
  agreedAt: number,        // timestamp of agreement
}
```

### Why SRP for Policies?

| Property                   | Benefit                                                                  |
| -------------------------- | ------------------------------------------------------------------------ |
| **Mutual authentication**  | Both parties prove their identity — no impersonation                     |
| **Non-repudiation**        | The SRP certificate proves both parties agreed to *this specific policy* |
| **Cryptographic binding**  | The policy hash is embedded in the SRP metadata, signed by both          |
| **Persistence**            | Stored locally, verifiable offline at any time                           |
| **No trusted third party** | No authority server needed — two peers agree directly                    |

---

## Capability Taxonomy

Capabilities follow the format `category.action:scope`:

| Category  | Actions                           | Scope examples            |
| --------- | --------------------------------- | ------------------------- |
| `fs`      | `read`, `write`, `delete`, `list` | `/workspace/**`, `/tmp/*` |
| `scm`     | `read`, `write`, `net`            | `github.com/org/*`        |
| `proc`    | `exec.build`, `exec.dev`          | `npm`, `cargo`            |
| `net`     | `egress.http`, `egress.dns`       | `api.company.com`         |
| `pkg`     | `lang`, `system`                  | —                         |
| `secrets` | `read`, `write`                   | —                         |

The `denied` list uses wildcard matching: `"secrets.*"` blocks all actions in the `secrets` category.

Scopes support glob patterns:
- `*` matches any segment (not crossing `/`)
- `**` matches everything (including `/`)

### Standalone Taxonomy Helpers

```typescript
import { parseCapability, matchScope, isCapabilityAllowed } from "@vaultys/id/src/execution";

parseCapability("fs.write:/workspace/src/**");
// → { category: "fs", action: "write", scope: "/workspace/src/**" }

matchScope("/workspace/**", "/workspace/deep/nested/file.ts");
// → true

isCapabilityAllowed("secrets.read", policy.scopes, policy.denied);
// → false
```

---

## Execution Intent

An intent is the agent's signed request to perform a specific action.

### Create an Intent (Agent)

```typescript
const intent = await agentEm.createIntent({
  tool: "git",
  argv: ["clone", "https://github.com/myorg/repo"],
  cwd: "/workspace",
  env_allowlist: ["PATH", "HOME"],
  requested_caps: [
    "scm.net:github.com/myorg/repo",
    "fs.write:/workspace/repo",
  ],
  inputs: {
    "package.json": "sha256:abc123...",
  },
});
```

The returned `intent` contains:
- `job_id` — unique UUID
- `timestamp` — creation time
- `nonce` — random bytes for replay protection
- `agent_id` — the agent's DID (`did:vaultys:...`)
- `signature` — the agent's cryptographic signature

### Verify an Intent (Anyone)

```typescript
const isValid = ExecutionManager.verifyIntent(intent, agentManager.vaultysId);
```

---

## Policy Evaluation (Broker)

Before executing, the broker evaluates the intent against the policy:

```typescript
const result = brokerEm.evaluateIntent(intent, signedPolicy);

switch (result.decision) {
  case "allow":
    // All requested capabilities are allowed, no constraints
    break;
  case "allow-with-constraints":
    // Allowed, but enforce result.constraints (e.g. max_runtime)
    break;
  case "deny":
    // Blocked — result.denied_caps lists the failing capabilities
    console.log("Denied:", result.denied_caps);
    break;
}
```

The evaluator checks:
1. Each `requested_caps` entry against `policy.scopes` and `policy.denied`
2. Shell metacharacters in `argv` when `no_shell_features` is set
3. Returns constraints for the sandbox to enforce

---

## Signed Receipts

After execution, the broker produces an immutable, signed receipt.

### Sign a Receipt (Broker)

```typescript
const outcome: ExecOutcome = {
  started: "2026-02-11T10:00:00Z",
  ended:   "2026-02-11T10:00:05Z",
  exit_code: 0,
  stdout_hash: "sha256:...",
  stderr_hash: "sha256:...",
  artifacts: { "dist/app.js": "sha256:..." },
  sandbox_config_hash: "sha256:...",
};

const receipt = await brokerEm.signReceipt(intent, signedPolicy, outcome);
```

### Verify a Receipt (Anyone)

```typescript
const isValid = ExecutionManager.verifyReceipt(receipt, brokerManager.vaultysId);
```

### Store & Retrieve Receipts

Receipts are automatically persisted during `acceptExecution`. You can also query them:

```typescript
const all = brokerEm.listReceipts();
const one = brokerEm.getReceipt(intent.job_id);
```

---

## Full SRP Round-Trip (over a Channel)

This is the main workflow: the agent and broker perform a mutually-authenticated handshake, then exchange intent/policy/receipt over the channel.

### Setup

```typescript
import { MemoryChannel } from "@vaultys/id";

const channel = MemoryChannel.createBidirectionnal();
// channel      → broker side
// channel.otherend → agent side
```

### Agent Side

```typescript
const receipt = await agentEm.requestExecution(
  channel.otherend!,   // agent's end of the channel
  intent,              // signed intent
  signedPolicy,        // signed policy bundle
);

if (receipt) {
  console.log("Execution succeeded, exit code:", receipt.exec.exit_code);
  console.log("Receipt verified:", ExecutionManager.verifyReceipt(receipt, brokerManager.vaultysId));
}
```

### Broker Side

```typescript
// The sandbox callback — this is where you run the actual command
const executor = async (intent: ExecutionIntent, evaluation: ExecutionResult): Promise<ExecOutcome> => {
  // Respect evaluation.constraints (e.g. max_runtime)
  // Run intent.tool with intent.argv in intent.cwd
  // ... your sandbox logic here ...

  return {
    started: new Date().toISOString(),
    ended: new Date().toISOString(),
    exit_code: 0,
    stdout_hash: "sha256:...",
    stderr_hash: "sha256:...",
  };
};

const receipt = await brokerEm.acceptExecution(
  channel,                        // broker's end of the channel
  authorityManager.vaultysId,     // expected policy signer
  executor,                       // sandbox callback
);
```

### Both Sides Together (e.g. in tests)

```typescript
const [agentReceipt, brokerReceipt] = await Promise.all([
  agentEm.requestExecution(channel.otherend!, intent, signedPolicy),
  brokerEm.acceptExecution(channel, authorityManager.vaultysId, executor),
]);
```

---

## Verification Flow (what the broker checks)

When `acceptExecution` is called, the broker performs these checks in order:

1. **SRP handshake** — mutual authentication between agent and broker
2. **Intent signature** — verifies the intent was signed by the authenticated agent
3. **Policy signature** — verifies the policy was signed by the expected authority
4. **Metadata binding** — confirms the policy hash in SRP metadata matches the received policy
5. **Policy evaluation** — checks all `requested_caps` against scopes/denied/constraints
6. **Execution** — delegates to the `onExecute` callback only if all checks pass
7. **Receipt** — signs and returns the outcome

If any check fails, the broker sends an error signal and throws.

---

## Optional: Accept/Reject Filter

Both `requestExecution` and `acceptExecution` accept an optional `accept` callback to filter peers during the SRP handshake:

```typescript
const receipt = await brokerEm.acceptExecution(
  channel,
  authorityManager.vaultysId,
  executor,
  async (agentVaultysId: VaultysId) => {
    // Only accept agents from your web of trust
    return brokerManager.getContact(agentVaultysId.did) !== null;
  },
);
```

---

## Error Handling

All verification failures throw descriptive errors:

| Error                                      | Cause                                                |
| ------------------------------------------ | ---------------------------------------------------- |
| `"SRP handshake failed"`                   | Mutual authentication did not complete               |
| `"Intent signature verification failed"`   | Intent was not signed by the SRP-authenticated agent |
| `"Policy signature verification failed"`   | Policy was not signed by the expected authority      |
| `"Policy hash mismatch with SRP metadata"` | Policy was swapped after the SRP handshake           |
| `"Intent denied by policy: ..."`           | One or more requested capabilities are denied        |
| `"Policy SRP handshake failed"`            | SRP handshake failed during policy agreement         |
| `"No policy found in SRP metadata"`        | Producer did not include policy in SRP metadata      |
| `"Policy hash mismatch in SRP metadata"`   | Policy content was tampered during SRP exchange      |
| `"Policy rejected by executor"`            | Executor's `onPolicy` callback returned false        |

---

## Running Tests

```bash
cd typescript
pnpm test -- --grep "Execution"
```

This runs 30 tests covering: taxonomy parsing, policy signing, SRP policy agreement, intent signing, evaluation, receipts, SRP round-trips, and error cases.
