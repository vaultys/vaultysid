#!/usr/bin/env tsx
/**
 * BROKER process — runs inside a Docker container.
 *
 * Workflow:
 *  1. Generate a fresh VaultysId (machine / ed25519) acting as both
 *     authority (policy signer) and broker (execution host).
 *  2. **Phase 1 – Policy distribution**: listen for an agent connection
 *     and send the authority-signed policy over TCP.
 *  3. **Phase 2 – Execution**: listen on port+1 for an execution
 *     request, verify intent + policy, run a simulated sandbox
 *     callback, sign a receipt and return it.
 *
 * Environment variables:
 *   BROKER_PORT  – base port to listen on (default: 9000)
 *   BROKER_NAME  – human-readable name for logs (default: broker)
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

const BROKER_PORT = parseInt(process.env.BROKER_PORT ?? "9000", 10);
const BROKER_NAME = process.env.BROKER_NAME ?? "broker";
const ALGORITHM = (process.env.ALGORITHM ?? "ed25519") as "ed25519" | "dilithium";

async function main() {
  console.log(`\n===  BROKER: ${BROKER_NAME}  ===`);
  console.log(`Algorithm : ${ALGORITHM}`);
  console.log(`Port      : ${BROKER_PORT} (policy), ${BROKER_PORT + 1} (exec)\n`);

  // ── 1. Identity ──
  const vaultysId = await VaultysId.generateMachine(ALGORITHM);
  const store = MemoryStorage();
  const idManager = new IdManager(vaultysId, store);
  idManager.setProtocolVersion(1);
  const execManager = new ExecutionManager(idManager);

  console.log(`[${BROKER_NAME}] DID = ${vaultysId.did}`);

  // ── Define and sign the policy ──
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
    not_before: Date.now(),             // valid from now
    not_after: Date.now() + 3600_000,   // valid for 1 hour
  };

  const signedPolicy = await execManager.signPolicy(policy);
  console.log(`[${BROKER_NAME}] Policy signed`);

  // ── 2. Phase 1 – Send signed policy to agent ──
  console.log(`\n[${BROKER_NAME}] Phase 1: listening for policy exchange on port ${BROKER_PORT}…`);
  const policyChannel = await TcpChannel.listen(BROKER_PORT);

  // Send signed policy + our VaultysId so agent can verify
  const policyPayload = Buffer.from(encode({
    policy: signedPolicy,
    authorityId: vaultysId.id,
  }));
  await policyChannel.send(policyPayload);
  await policyChannel.close();

  console.log(`[${BROKER_NAME}] Signed policy sent to agent`);

  // ── 3. Phase 2 – Execution ──
  console.log(`\n[${BROKER_NAME}] Phase 2: listening for execution request on port ${BROKER_PORT + 1}…`);
  const execChannel = await TcpChannel.listen(BROKER_PORT + 1);

  // Simulated execution callback
  const onExecute = async (intent: ExecutionIntent, result: ExecutionResult): Promise<ExecOutcome> => {
    console.log(`[${BROKER_NAME}] Executing: ${intent.tool} ${intent.argv.join(" ")}`);
    console.log(`[${BROKER_NAME}] Decision : ${result.decision}`);
    console.log(`[${BROKER_NAME}] Caps     : ${result.allowed_caps?.join(", ")}`);

    const started = new Date().toISOString();
    // Simulate some work
    await new Promise((r) => setTimeout(r, 200));
    const ended = new Date().toISOString();

    return {
      started,
      ended,
      exit_code: 0,
      stdout_hash: "abc123",
      stderr_hash: "",
      sandbox_config_hash: "sandbox-v1",
    };
  };

  const receipt = await execManager.acceptExecution(
    execChannel,
    vaultysId, // authority = self in this demo
    onExecute,
  );

  await execChannel.close();

  console.log(`\n[${BROKER_NAME}] ✅ Execution complete, receipt signed`);
  console.log(`[${BROKER_NAME}]   intent_hash : ${receipt.intent_hash}`);
  console.log(`[${BROKER_NAME}]   exit_code   : ${receipt.exec.exit_code}`);

  // Verify our own receipt
  const valid = ExecutionManager.verifyReceipt(receipt, vaultysId);
  console.log(`[${BROKER_NAME}]   self_verify : ${valid}`);

  // Check stored receipts
  const receipts = execManager.listReceipts();
  console.log(`[${BROKER_NAME}]   stored      : ${receipts.length} receipt(s)`);

  console.log(`\n[${BROKER_NAME}] ✅ Integration test PASSED`);
  process.exit(0);
}

main().catch((err) => {
  console.error(`[${BROKER_NAME}] FATAL:`, err);
  process.exit(1);
});
