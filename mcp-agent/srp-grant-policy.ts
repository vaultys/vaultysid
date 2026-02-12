#!/usr/bin/env node
/**
 * SRP Policy Grant CLI
 *
 * Uses the VaultysID Secure Remote Protocol (SRP) to establish a policy
 * agreement between a producer (authority) and an executor (MCP server).
 * This is the canonical VaultysID pattern — both sides exchange certificates,
 * and the policy is cryptographically bound to the SRP metadata.
 *
 * This replaces the manual file-based grant-policy.ts when both parties
 * can communicate over a channel (e.g. in-process via MemoryChannel,
 * or over a network via WebSocket/TCP).
 *
 * Usage:
 *   pnpm srp-grant   # runs a local in-process SRP handshake
 *
 * What happens:
 *   1. Producer and executor identities are loaded or created
 *   2. A MemoryChannel (bidirectional) connects them
 *   3. grantPolicy() and acceptPolicy() run concurrently
 *   4. Both sides store the agreed policy + SRP certificate
 *   5. The executor can now evaluate intents against the stored policy
 */

import * as fs from "node:fs";
import * as path from "node:path";
import {
  IdManager,
  VaultysId,
  MemoryStorage,
  MemoryChannel,
  ExecutionManager,
  Challenger,
} from "@vaultys/id";
import type { PolicyBundle } from "@vaultys/id";

// ── Configuration ──

const args = process.argv.slice(2);

function getArg(name: string, defaultValue: string): string {
  const idx = args.indexOf(`--${name}`);
  if (idx !== -1 && args[idx + 1]) return args[idx + 1];
  return defaultValue;
}

const policyFile = getArg("policy", "policy.example.json");
const hours = parseInt(getArg("hours", "24"), 10);
const workspaceRoot = path.resolve(getArg("workspace", "workspace"));

const PRODUCER_FILE = "authority.secret.json";
const EXECUTOR_FILE = "server.identity.json";

// ── Helpers ──

async function loadOrCreateIdentity(filePath: string, label: string): Promise<IdManager> {
  if (fs.existsSync(filePath)) {
    const data = fs.readFileSync(filePath, "utf-8");
    const store = MemoryStorage().fromString(data);
    const idm = await IdManager.fromStore(store);
    idm.setProtocolVersion(1);
    console.log(`✓ Loaded ${label}: ${idm.vaultysId.did}`);
    return idm;
  }

  const store = MemoryStorage();
  const idm = await IdManager.fromStore(store);
  idm.setProtocolVersion(1);
  fs.writeFileSync(filePath, store.toString());
  console.log(`✓ Generated ${label}: ${idm.vaultysId.did}`);
  console.log(`  Saved to: ${filePath}`);
  return idm;
}

// ── Main ──

async function main() {
  console.log("╔══════════════════════════════════════════════════╗");
  console.log("║  VaultysID SRP Policy Agreement                 ║");
  console.log("╚══════════════════════════════════════════════════╝");
  console.log();

  // 1. Load or create identities
  const producer = await loadOrCreateIdentity(PRODUCER_FILE, "producer (authority)");
  const executor = await loadOrCreateIdentity(EXECUTOR_FILE, "executor (MCP server)");

  // 2. Load and prepare policy
  if (!fs.existsSync(policyFile)) {
    console.error(`✗ Policy file not found: ${policyFile}`);
    process.exit(1);
  }

  const policyTemplate = JSON.parse(fs.readFileSync(policyFile, "utf-8"));

  // Substitute {{WORKSPACE}} placeholders
  if (policyTemplate.scopes) {
    for (const [key, patterns] of Object.entries(policyTemplate.scopes)) {
      if (Array.isArray(patterns)) {
        policyTemplate.scopes[key] = patterns.map((p: string) =>
          p.replace(/\{\{WORKSPACE\}\}/g, workspaceRoot),
        );
      }
    }
  }

  // Add time bounds
  const now = Date.now();
  const policy: Omit<PolicyBundle, "signature"> = {
    ...policyTemplate,
    not_before: now,
    not_after: now + hours * 3600_000,
  };

  console.log();
  console.log(`✓ Policy loaded: ${policyFile}`);
  console.log(`  Workspace root: ${workspaceRoot}`);
  console.log(`  Valid from: ${new Date(policy.not_before!).toISOString()}`);
  console.log(`  Expires:    ${new Date(policy.not_after!).toISOString()}`);

  // 3. Create ExecutionManagers
  const producerEm = new ExecutionManager(producer);
  const executorEm = new ExecutionManager(executor);

  // 4. Create bidirectional channel (in-process demo)
  const channel = MemoryChannel.createBidirectionnal();
  if (!channel.otherend) {
    throw new Error("Failed to create bidirectional channel");
  }

  console.log();
  console.log("⟳ Starting SRP handshake...");

  // 5. Run grantPolicy / acceptPolicy concurrently
  const [counterpart, result] = await Promise.all([
    producerEm.grantPolicy(channel, policy),
    executorEm.acceptPolicy(channel.otherend),
  ]);

  // 6. Verify
  console.log();
  console.log("✓ SRP handshake complete!");
  console.log(`  Producer sees executor: ${counterpart.did}`);
  console.log(`  Executor sees producer: ${result.counterpart.did}`);

  // Verify the stored policy certificates
  const producerStored = producerEm.getPolicy(executor.vaultysId.did);
  const executorStored = executorEm.getPolicy(producer.vaultysId.did);

  if (producerStored) {
    const valid = await ExecutionManager.verifyStoredPolicy(producerStored);
    console.log(`  Producer certificate: ${valid ? "✓ valid" : "✗ INVALID"}`);
  }

  if (executorStored) {
    const valid = await ExecutionManager.verifyStoredPolicy(executorStored);
    console.log(`  Executor certificate: ${valid ? "✓ valid" : "✗ INVALID"}`);
  }

  // 7. Persist updated identities (with policy substore)
  // The stores were already modified by grantPolicy/acceptPolicy
  fs.writeFileSync(PRODUCER_FILE, producer.store.toString());
  fs.writeFileSync(EXECUTOR_FILE, executor.store.toString());

  // 8. Also export files for backward compatibility with file-based server.ts
  // Export the signed policy (from the SRP-stored version)
  if (executorStored) {
    const signedPolicy = executorStored.policy;
    // For file-based usage, we also need the authority's signed version
    // The SRP approach stores the policy without a separate signature field;
    // instead the SRP certificate binds the policy cryptographically.
    // For the file-based server flow, we sign the policy explicitly too.
    const explicitSigned = await producerEm.signPolicy(policy);
    const serializable = {
      ...explicitSigned,
      signature: explicitSigned.signature
        ? Buffer.from(explicitSigned.signature).toString("base64")
        : undefined,
    };
    fs.writeFileSync("policy.signed.json", JSON.stringify(serializable, null, 2));
    console.log(`  policy.signed.json: written (for file-based server mode)`);
  }

  // Export authority public identity
  const vid = producer.vaultysId;
  fs.writeFileSync("authority.identity.json", JSON.stringify({
    did: vid.did,
    id: Buffer.from(vid.id).toString("base64"),
    fingerprint: vid.fingerprint,
  }, null, 2));

  // 9. Summary
  console.log();
  console.log("┌──────────────────────────────────────────────┐");
  console.log("│  SRP Policy Agreement Complete!              │");
  console.log("├──────────────────────────────────────────────┤");
  console.log(`│  Producer DID: ${producer.vaultysId.did.slice(0, 28)}...│`);
  console.log(`│  Executor DID: ${executor.vaultysId.did.slice(0, 28)}...│`);
  console.log("│                                              │");
  console.log("│  Policy stored in both identity stores       │");
  console.log("│  SRP certificates bind the agreement         │");
  console.log("│                                              │");
  console.log("│  To start the MCP server:                    │");
  console.log("│    pnpm start                                │");
  console.log("│                                              │");
  console.log("│  The server will load the policy from its    │");
  console.log("│  identity store (SRP) or from signed file.   │");
  console.log("└──────────────────────────────────────────────┘");

  // Show stored policies
  const allPolicies = executorEm.listPolicies();
  console.log(`\nExecutor has ${allPolicies.length} stored policy agreement(s).`);
}

main().catch((err) => {
  console.error("Error:", err);
  process.exit(1);
});
