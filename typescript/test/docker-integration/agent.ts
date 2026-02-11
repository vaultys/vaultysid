#!/usr/bin/env tsx
/**
 * AGENT process — runs inside a Docker container.
 *
 * Workflow:
 *  1. Generate a fresh VaultysId (person / ed25519).
 *  2. **Phase 1 – Policy exchange**: connect to the broker, receive the
 *     authority-signed policy bundle over TCP.
 *  3. **Phase 2 – Execution request**: create a signed intent, connect
 *     again and submit it to the broker via `requestExecution`.
 *  4. Verify the returned receipt and exit 0 on success.
 *
 * Environment variables:
 *   BROKER_HOST  – hostname of the broker container (default: broker)
 *   BROKER_PORT  – base port of the broker (default: 9000)
 *   AGENT_NAME   – human-readable name for logs (default: agent)
 *   ALGORITHM    – "ed25519" or "dilithium" (default: ed25519)
 */

import { encode, decode } from "@msgpack/msgpack";
import VaultysId from "../../src/VaultysId";
import IdManager from "../../src/IdManager";
import { MemoryStorage } from "../../src/MemoryStorage";
import ExecutionManager from "../../src/execution/ExecutionManager";
import { TcpChannel } from "./TcpChannel";
import { Buffer } from "buffer/";
import type { PolicyBundle } from "../../src/execution/types";

const BROKER_HOST = process.env.BROKER_HOST ?? "broker";
const BROKER_PORT = parseInt(process.env.BROKER_PORT ?? "9000", 10);
const AGENT_NAME = process.env.AGENT_NAME ?? "agent";
const ALGORITHM = (process.env.ALGORITHM ?? "ed25519") as "ed25519" | "dilithium";

// Retry helper for TCP connects (broker may not be ready yet)
async function connectWithRetry(host: string, port: number, retries = 30, delayMs = 1000): Promise<TcpChannel> {
  for (let i = 0; i < retries; i++) {
    try {
      return await TcpChannel.connect(host, port);
    } catch {
      if (i === retries - 1) throw new Error(`Cannot connect to ${host}:${port} after ${retries} attempts`);
      console.log(`[${AGENT_NAME}] Waiting for ${host}:${port}… (${i + 1}/${retries})`);
      await new Promise((r) => setTimeout(r, delayMs));
    }
  }
  throw new Error("unreachable");
}

async function main() {
  console.log(`\n===  AGENT: ${AGENT_NAME}  ===`);
  console.log(`Algorithm : ${ALGORITHM}`);
  console.log(`Broker    : ${BROKER_HOST}:${BROKER_PORT}\n`);

  // ── 1. Identity ──
  const vaultysId = await VaultysId.generatePerson(ALGORITHM);
  const store = MemoryStorage();
  const idManager = new IdManager(vaultysId, store);
  idManager.setProtocolVersion(1);
  const execManager = new ExecutionManager(idManager);

  console.log(`[${AGENT_NAME}] DID = ${vaultysId.did}`);

  // ── 2. Phase 1 – Receive authority-signed policy from broker ──
  console.log(`\n[${AGENT_NAME}] Phase 1: connecting to broker for policy exchange…`);
  const policyChannel = await connectWithRetry(BROKER_HOST, BROKER_PORT);

  // Receive the broker's signed policy + its serialized VaultysId
  const policyMsg = await policyChannel.receive();
  const { policy, authorityId: authorityIdBytes } = decode(policyMsg) as {
    policy: PolicyBundle;
    authorityId: Uint8Array;
  };
  const brokerVaultysId = VaultysId.fromId(Buffer.from(authorityIdBytes));
  await policyChannel.close();

  console.log(`[${AGENT_NAME}] Received signed policy from broker ${brokerVaultysId.did}`);
  console.log(`[${AGENT_NAME}] Policy scopes:`, JSON.stringify(policy.scopes));

  // Verify the authority's signature on the policy
  const policyValid = ExecutionManager.verifyPolicy(policy, brokerVaultysId);
  console.log(`[${AGENT_NAME}] Policy signature valid: ${policyValid}`);
  if (!policyValid) {
    console.error(`[${AGENT_NAME}] ❌ Policy signature invalid`);
    process.exit(1);
  }

  // ── 3. Phase 2 – Create & send execution intent ──
  console.log(`\n[${AGENT_NAME}] Phase 2: creating execution intent…`);

  const intent = await execManager.createIntent({
    tool: "echo",
    argv: ["Hello", "from", AGENT_NAME],
    cwd: "/tmp",
    requested_caps: ["proc.exec:echo"],
    inputs: {},
  });

  console.log(`[${AGENT_NAME}] Intent job_id = ${intent.job_id}`);

  // Give broker time to switch to phase-2 listener
  await new Promise((r) => setTimeout(r, 500));

  const execChannel = await connectWithRetry(BROKER_HOST, BROKER_PORT + 1);
  const receipt = await execManager.requestExecution(execChannel, intent, policy);
  await execChannel.close();

  if (!receipt) {
    console.error(`[${AGENT_NAME}] ❌ No receipt received`);
    process.exit(1);
  }

  console.log(`\n[${AGENT_NAME}] ✅ Receipt received!`);
  console.log(`[${AGENT_NAME}]   intent_hash  : ${receipt.intent_hash}`);
  console.log(`[${AGENT_NAME}]   exit_code    : ${receipt.exec.exit_code}`);
  console.log(`[${AGENT_NAME}]   started      : ${receipt.exec.started}`);
  console.log(`[${AGENT_NAME}]   ended        : ${receipt.exec.ended}`);

  // Verify the receipt
  const valid = ExecutionManager.verifyReceipt(receipt, brokerVaultysId);
  console.log(`[${AGENT_NAME}]   valid_sig    : ${valid}`);

  if (!valid) {
    console.error(`[${AGENT_NAME}] ❌ Receipt signature invalid`);
    process.exit(1);
  }

  console.log(`\n[${AGENT_NAME}] ✅ Integration test PASSED`);
  process.exit(0);
}

main().catch((err) => {
  console.error(`[${AGENT_NAME}] FATAL:`, err);
  process.exit(1);
});
