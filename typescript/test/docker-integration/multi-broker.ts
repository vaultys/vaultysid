#!/usr/bin/env tsx
/**
 * MULTI-BROKER process — handles multiple sequential agents.
 *
 * Workflow:
 *  1. Generate identity.
 *  2. Listen for AGENT_COUNT policy agreements (phase 1 on port P).
 *  3. Listen for AGENT_COUNT execution requests  (phase 2 on port P+1).
 *
 * Environment variables:
 *   BROKER_PORT   – base port (default: 9020)
 *   BROKER_NAME   – human-readable name (default: multi-broker)
 *   AGENT_COUNT   – how many agents to expect (default: 2)
 *   ALGORITHM     – "ed25519" or "dilithium" (default: ed25519)
 */

import { encode } from "@msgpack/msgpack";
import VaultysId from "../../src/VaultysId";
import IdManager from "../../src/IdManager";
import { MemoryStorage } from "../../src/MemoryStorage";
import ExecutionManager from "../../src/execution/ExecutionManager";
import { TcpChannel } from "./TcpChannel";
import { Buffer } from "buffer/";
import type { ExecutionIntent, ExecutionResult, ExecOutcome, PolicyBundle } from "../../src/execution/types";

const BROKER_PORT = parseInt(process.env.BROKER_PORT ?? "9020", 10);
const BROKER_NAME = process.env.BROKER_NAME ?? "multi-broker";
const AGENT_COUNT = parseInt(process.env.AGENT_COUNT ?? "2", 10);
const ALGORITHM = (process.env.ALGORITHM ?? "ed25519") as "ed25519" | "dilithium";

async function main() {
  console.log(`\n===  MULTI-BROKER: ${BROKER_NAME}  ===`);
  console.log(`Expecting ${AGENT_COUNT} agents\n`);

  const vaultysId = await VaultysId.generateMachine(ALGORITHM);
  const store = MemoryStorage();
  const idManager = new IdManager(vaultysId, store);
  idManager.setProtocolVersion(1);
  const execManager = new ExecutionManager(idManager);

  console.log(`[${BROKER_NAME}] DID = ${vaultysId.did}`);

  const policy: Omit<PolicyBundle, "signature"> = {
    version: "1.0",
    scopes: {
      "proc.exec": ["echo", "ls", "cat"],
      "fs.read": ["**"],
    },
    denied: ["proc.privilege"],
    constraints: { no_shell_features: true },
    not_before: Date.now(),
    not_after: Date.now() + 3600_000,
  };

  const signedPolicy = await execManager.signPolicy(policy);

  // ── Phase 1: send policy to agents one by one ──
  for (let i = 0; i < AGENT_COUNT; i++) {
    console.log(`\n[${BROKER_NAME}] Phase 1: waiting for agent ${i + 1}/${AGENT_COUNT}…`);
    const ch = await TcpChannel.listen(BROKER_PORT);
    const policyPayload = Buffer.from(encode({
      policy: signedPolicy,
      authorityId: vaultysId.id,
    }));
    await ch.send(policyPayload);
    await ch.close();
    console.log(`[${BROKER_NAME}] Policy sent to agent ${i + 1}`);
  }

  // ── Phase 2: handle executions one by one ──
  for (let i = 0; i < AGENT_COUNT; i++) {
    console.log(`\n[${BROKER_NAME}] Phase 2: waiting for execution ${i + 1}/${AGENT_COUNT}…`);
    const ch = await TcpChannel.listen(BROKER_PORT + 1);

    const onExecute = async (intent: ExecutionIntent, result: ExecutionResult): Promise<ExecOutcome> => {
      console.log(`[${BROKER_NAME}] Executing for agent ${i + 1}: ${intent.tool} ${intent.argv.join(" ")}`);
      const started = new Date().toISOString();
      await new Promise((r) => setTimeout(r, 100));
      return {
        started,
        ended: new Date().toISOString(),
        exit_code: 0,
        stdout_hash: `result-${i + 1}`,
        stderr_hash: "",
      };
    };

    const receipt = await execManager.acceptExecution(ch, vaultysId, onExecute);
    await ch.close();
    console.log(`[${BROKER_NAME}] Execution ${i + 1} done, exit_code=${receipt.exec.exit_code}`);
  }

  const receipts = execManager.listReceipts();
  console.log(`\n[${BROKER_NAME}] Total receipts: ${receipts.length}`);
  console.log(`[${BROKER_NAME}] ✅ Multi-agent integration PASSED`);
  process.exit(0);
}

main().catch((err) => {
  console.error(`[${BROKER_NAME}] FATAL:`, err);
  process.exit(1);
});
