#!/usr/bin/env tsx
/**
 * MULTI-AGENT process — one of N agents connecting to a multi-broker.
 *
 * Environment variables:
 *   BROKER_HOST  – hostname of the multi-broker (default: multi-broker)
 *   BROKER_PORT  – base port of the multi-broker (default: 9020)
 *   AGENT_NAME   – human-readable name (default: multi-agent-N)
 *   AGENT_INDEX  – 0-based index used for staggered timing (default: 0)
 *   ALGORITHM    – "ed25519" or "dilithium" (default: ed25519)
 */

import { decode } from "@msgpack/msgpack";
import VaultysId from "../../src/VaultysId";
import IdManager from "../../src/IdManager";
import { MemoryStorage } from "../../src/MemoryStorage";
import ExecutionManager from "../../src/execution/ExecutionManager";
import { TcpChannel } from "./TcpChannel";
import { Buffer } from "buffer/";
import type { PolicyBundle } from "../../src/execution/types";

const BROKER_HOST = process.env.BROKER_HOST ?? "multi-broker";
const BROKER_PORT = parseInt(process.env.BROKER_PORT ?? "9020", 10);
const AGENT_NAME = process.env.AGENT_NAME ?? `multi-agent-${process.env.AGENT_INDEX ?? "0"}`;
const AGENT_INDEX = parseInt(process.env.AGENT_INDEX ?? "0", 10);
const ALGORITHM = (process.env.ALGORITHM ?? "ed25519") as "ed25519" | "dilithium";

async function connectWithRetry(host: string, port: number, retries = 30, delayMs = 1000): Promise<TcpChannel> {
  for (let i = 0; i < retries; i++) {
    try {
      return await TcpChannel.connect(host, port);
    } catch {
      if (i === retries - 1) throw new Error(`Cannot connect to ${host}:${port} after ${retries} attempts`);
      await new Promise((r) => setTimeout(r, delayMs));
    }
  }
  throw new Error("unreachable");
}

async function main() {
  // Stagger start to sequence connections to the single-threaded broker
  const staggerDelay = AGENT_INDEX * 3000;
  console.log(`\n===  ${AGENT_NAME}  ===`);
  console.log(`Staggering start by ${staggerDelay}ms (index=${AGENT_INDEX})\n`);
  await new Promise((r) => setTimeout(r, staggerDelay));

  const vaultysId = await VaultysId.generatePerson(ALGORITHM);
  const store = MemoryStorage();
  const idManager = new IdManager(vaultysId, store);
  idManager.setProtocolVersion(1);
  const execManager = new ExecutionManager(idManager);

  console.log(`[${AGENT_NAME}] DID = ${vaultysId.did}`);

  // ── Phase 1 ──
  console.log(`[${AGENT_NAME}] Phase 1: receiving policy…`);
  const policyChannel = await connectWithRetry(BROKER_HOST, BROKER_PORT);
  const policyMsg = await policyChannel.receive();
  const { policy, authorityId: authorityIdBytes } = decode(policyMsg) as {
    policy: PolicyBundle;
    authorityId: Uint8Array;
  };
  const brokerId = VaultysId.fromId(Buffer.from(authorityIdBytes));
  await policyChannel.close();
  console.log(`[${AGENT_NAME}] Policy received from ${brokerId.did}`);

  // ── Phase 2 ──
  console.log(`[${AGENT_NAME}] Phase 2: sending execution intent…`);
  const intent = await execManager.createIntent({
    tool: "echo",
    argv: ["Hello", "from", AGENT_NAME],
    cwd: "/tmp",
    requested_caps: ["proc.exec:echo"],
    inputs: {},
  });

  const signedPolicy = policy; // already signed by the broker
  await new Promise((r) => setTimeout(r, 500));

  const execChannel = await connectWithRetry(BROKER_HOST, BROKER_PORT + 1);
  const receipt = await execManager.requestExecution(execChannel, intent, signedPolicy);
  await execChannel.close();

  if (!receipt) {
    console.error(`[${AGENT_NAME}] ❌ No receipt`);
    process.exit(1);
  }

  const valid = ExecutionManager.verifyReceipt(receipt, brokerId);
  console.log(`[${AGENT_NAME}] Receipt valid: ${valid}, exit_code: ${receipt.exec.exit_code}`);

  if (!valid) {
    console.error(`[${AGENT_NAME}] ❌ Receipt invalid`);
    process.exit(1);
  }

  console.log(`[${AGENT_NAME}] ✅ PASSED`);
  process.exit(0);
}

main().catch((err) => {
  console.error(`[${AGENT_NAME}] FATAL:`, err);
  process.exit(1);
});
