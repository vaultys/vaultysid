#!/usr/bin/env tsx
/**
 * DENIED-AGENT process — runs inside a Docker container.
 *
 * Same as agent.ts but requests a capability that the broker's policy
 * explicitly denies (`tool:execute:rm`). The broker should reject the
 * intent and this agent should exit 0 confirming the denial.
 *
 * Environment variables:
 *   BROKER_HOST  – hostname of the broker (default: denied-broker)
 *   BROKER_PORT  – base port of the broker (default: 9010)
 *   AGENT_NAME   – human-readable name (default: denied-agent)
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

const BROKER_HOST = process.env.BROKER_HOST ?? "denied-broker";
const BROKER_PORT = parseInt(process.env.BROKER_PORT ?? "9010", 10);
const AGENT_NAME = process.env.AGENT_NAME ?? "denied-agent";
const ALGORITHM = (process.env.ALGORITHM ?? "ed25519") as "ed25519" | "dilithium";

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
  console.log(`\n===  DENIED-AGENT: ${AGENT_NAME}  ===`);
  console.log(`Broker: ${BROKER_HOST}:${BROKER_PORT}\n`);

  // ── 1. Identity ──
  const vaultysId = await VaultysId.generatePerson(ALGORITHM);
  const store = MemoryStorage();
  const idManager = new IdManager(vaultysId, store);
  idManager.setProtocolVersion(1);
  const execManager = new ExecutionManager(idManager);

  console.log(`[${AGENT_NAME}] DID = ${vaultysId.did}`);

  // ── 2. Phase 1 – Receive policy ──
  console.log(`\n[${AGENT_NAME}] Phase 1: receiving policy from broker…`);
  const policyChannel = await connectWithRetry(BROKER_HOST, BROKER_PORT);
  const policyMsg = await policyChannel.receive();
  const { policy, authorityId: authorityIdBytes } = decode(policyMsg) as {
    policy: PolicyBundle;
    authorityId: Uint8Array;
  };
  const brokerVaultysId = VaultysId.fromId(Buffer.from(authorityIdBytes));
  await policyChannel.close();

  console.log(`[${AGENT_NAME}] Policy received from broker ${brokerVaultysId.did}`);

  // ── 3. Phase 2 – Request denied capability ──
  console.log(`\n[${AGENT_NAME}] Phase 2: requesting denied capability (tool:execute:rm)…`);

  const intent = await execManager.createIntent({
    tool: "rm",
    argv: ["-rf", "/important-data"],
    cwd: "/tmp",
    requested_caps: ["fs.delete:/important-data"],
    inputs: {},
  });

  const signedPolicy = policy; // already signed by the broker
  await new Promise((r) => setTimeout(r, 500));

  const execChannel = await connectWithRetry(BROKER_HOST, BROKER_PORT + 1);
  const receipt = await execManager.requestExecution(execChannel, intent, signedPolicy);
  await execChannel.close();

  if (receipt === null) {
    console.log(`\n[${AGENT_NAME}] ✅ Correctly received null (denied) – PASSED`);
    process.exit(0);
  }

  // If somehow we got a receipt, that's a failure
  console.error(`[${AGENT_NAME}] ❌ Expected denial but got receipt!`);
  process.exit(1);
}

main().catch((err) => {
  // The broker throwing "Intent denied" and closing the channel is expected
  if (err.message?.includes("denied") || err.message?.includes("Empty")) {
    console.log(`\n[${AGENT_NAME}] ✅ Got expected error: ${err.message} – PASSED`);
    process.exit(0);
  }
  console.error(`[${AGENT_NAME}] FATAL:`, err);
  process.exit(1);
});
