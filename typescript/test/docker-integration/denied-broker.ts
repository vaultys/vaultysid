#!/usr/bin/env tsx
/**
 * DENIED-BROKER process — runs inside a Docker container.
 *
 * Mirrors broker.ts but is used in the "denied capability" scenario.
 * It proposes the same policy and expects the agent's intent to be
 * denied during evaluation.
 *
 * Environment variables:
 *   BROKER_PORT  – base port (default: 9010)
 *   BROKER_NAME  – human-readable (default: denied-broker)
 *   ALGORITHM    – "ed25519" or "dilithium" (default: ed25519)
 */

import { encode } from "@msgpack/msgpack";
import VaultysId from "../../src/VaultysId";
import IdManager from "../../src/IdManager";
import { MemoryStorage } from "../../src/MemoryStorage";
import ExecutionManager from "../../src/execution/ExecutionManager";
import { TcpChannel } from "./TcpChannel";
import { Buffer } from "buffer/";
import type { ExecutionIntent, ExecutionResult, ExecOutcome, PolicyBundle } from "../../src/execution/types";

const BROKER_PORT = parseInt(process.env.BROKER_PORT ?? "9010", 10);
const BROKER_NAME = process.env.BROKER_NAME ?? "denied-broker";
const ALGORITHM = (process.env.ALGORITHM ?? "ed25519") as "ed25519" | "dilithium";

async function main() {
  console.log(`\n===  DENIED-BROKER: ${BROKER_NAME}  ===`);
  console.log(`Port: ${BROKER_PORT} (policy), ${BROKER_PORT + 1} (exec)\n`);

  // ── 1. Identity ──
  const vaultysId = await VaultysId.generateMachine(ALGORITHM);
  const store = MemoryStorage();
  const idManager = new IdManager(vaultysId, store);
  idManager.setProtocolVersion(1);
  const execManager = new ExecutionManager(idManager);

  console.log(`[${BROKER_NAME}] DID = ${vaultysId.did}`);

  // Same policy as main broker
  const policy: Omit<PolicyBundle, "signature"> = {
    version: "1.0",
    scopes: {
      "proc.exec": ["echo", "ls", "cat"],
      "fs.read": ["**"],
    },
    denied: ["proc.privilege", "secrets.*"],
    constraints: {
      max_runtime: 30000,
      no_shell_features: true,
    },
  };

  // ── 2. Phase 1 – Send signed policy ──
  console.log(`\n[${BROKER_NAME}] Phase 1: sending signed policy…`);
  const signedPolicy = await execManager.signPolicy(policy);
  const policyChannel = await TcpChannel.listen(BROKER_PORT);
  const policyPayload = Buffer.from(encode({
    policy: signedPolicy,
    authorityId: vaultysId.id,
  }));
  await policyChannel.send(policyPayload);
  await policyChannel.close();
  console.log(`[${BROKER_NAME}] Signed policy sent`);

  // ── 3. Phase 2 – Accept execution (expect denial) ──
  console.log(`\n[${BROKER_NAME}] Phase 2: listening for (expected-to-be-denied) execution…`);
  const execChannel = await TcpChannel.listen(BROKER_PORT + 1);

  const onExecute = async (intent: ExecutionIntent, result: ExecutionResult): Promise<ExecOutcome> => {
    // Should not reach here because the intent should be denied
    console.error(`[${BROKER_NAME}] ❌ onExecute was called — intent should have been denied!`);
    return {
      started: new Date().toISOString(),
      ended: new Date().toISOString(),
      exit_code: 1,
    };
  };

  try {
    await execManager.acceptExecution(execChannel, vaultysId, onExecute);
    // If we get here, this is wrong — the intent should have been denied
    console.error(`[${BROKER_NAME}] ❌ Expected denial but execution succeeded`);
    process.exit(1);
  } catch (err: any) {
    if (err.message?.includes("denied")) {
      console.log(`\n[${BROKER_NAME}] ✅ Correctly denied intent: ${err.message} – PASSED`);
      await execChannel.close();
      process.exit(0);
    }
    throw err;
  }
}

main().catch((err) => {
  console.error(`[${BROKER_NAME}] FATAL:`, err);
  process.exit(1);
});
