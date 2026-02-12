#!/usr/bin/env node
/**
 * Grant Policy CLI
 *
 * Creates an authority identity and signs a policy bundle.
 * Outputs:
 *   - policy.signed.json       — the signed policy (loaded by the MCP server)
 *   - authority.identity.json  — the authority's public key (for verification)
 *   - authority.secret.json    — the authority's full identity (keep safe!)
 *
 * Usage:
 *   pnpm grant-policy                          # uses policy.example.json, 24h validity
 *   pnpm grant-policy -- --policy custom.json  # custom policy file
 *   pnpm grant-policy -- --hours 2             # 2-hour validity window
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { ExecutionManager, VaultysId, MemoryStorage, IdManager } from "@vaultys/id";
import type { PolicyBundle } from "@vaultys/id";

// ── Parse args ──
const args = process.argv.slice(2);

function getArg(name: string, defaultValue: string): string {
  const idx = args.indexOf(`--${name}`);
  if (idx !== -1 && args[idx + 1]) return args[idx + 1];
  return defaultValue;
}

const policyFile = getArg("policy", "policy.example.json");
const hours = parseInt(getArg("hours", "24"), 10);
const workspaceRoot = path.resolve(getArg("workspace", "workspace"));

const AUTHORITY_IDENTITY_FILE = "authority.secret.json";
const AUTHORITY_PUBLIC_FILE = "authority.identity.json";
const SIGNED_POLICY_FILE = "policy.signed.json";

async function main() {
  // 1. Load or create authority identity
  let authorityIdm: IdManager;

  if (fs.existsSync(AUTHORITY_IDENTITY_FILE)) {
    const data = fs.readFileSync(AUTHORITY_IDENTITY_FILE, "utf-8");
    const store = MemoryStorage().fromString(data);
    const loaded = await IdManager.fromStore(store);
    if (!loaded) throw new Error("Failed to load authority identity");
    authorityIdm = loaded;
    authorityIdm.setProtocolVersion(1);
    console.log(`✓ Loaded authority identity: ${authorityIdm.vaultysId.did}`);

  } else {
    const store = MemoryStorage();
    authorityIdm = await IdManager.fromStore(store);
    authorityIdm.setProtocolVersion(1);
    fs.writeFileSync(AUTHORITY_IDENTITY_FILE, store.toString());
    console.log(`✓ Generated authority identity: ${authorityIdm.vaultysId.did}`);
    console.log(`  Saved to: ${AUTHORITY_IDENTITY_FILE}`);
  }

  // 2. Export authority public identity for the server
  // VaultysId.id contains the full public identity (can be reconstructed with VaultysId.fromId)
  const vid = authorityIdm.vaultysId;
  fs.writeFileSync(AUTHORITY_PUBLIC_FILE, JSON.stringify({
    did: vid.did,
    id: Buffer.from(vid.id).toString("base64"),
    fingerprint: vid.fingerprint,
  }, null, 2));
  console.log(`✓ Authority public identity saved to: ${AUTHORITY_PUBLIC_FILE}`);

  // 3. Load policy template
  if (!fs.existsSync(policyFile)) {
    console.error(`✗ Policy file not found: ${policyFile}`);
    process.exit(1);
  }

  const policyTemplate = JSON.parse(fs.readFileSync(policyFile, "utf-8"));
  console.log(`✓ Loaded policy template: ${policyFile}`);

  // 3a. Substitute {{WORKSPACE}} placeholder with the actual workspace path
  if (policyTemplate.scopes) {
    for (const [key, patterns] of Object.entries(policyTemplate.scopes)) {
      if (Array.isArray(patterns)) {
        policyTemplate.scopes[key] = patterns.map((p: string) =>
          p.replace(/\{\{WORKSPACE\}\}/g, workspaceRoot),
        );
      }
    }
  }
  console.log(`  Workspace root: ${workspaceRoot}`);

  // 4. Add time bounds
  const now = Date.now();
  const policy: Omit<PolicyBundle, "signature"> = {
    ...policyTemplate,
    not_before: now,
    not_after: now + hours * 3600_000,
  };

  console.log(`  Valid from: ${new Date(policy.not_before!).toISOString()}`);
  console.log(`  Expires:    ${new Date(policy.not_after!).toISOString()}`);
  console.log(`  Duration:   ${hours} hours`);

  // 5. Sign the policy
  const em = new ExecutionManager(authorityIdm);
  const signed = await em.signPolicy(policy);

  // 6. Serialize (convert Buffer signature to base64 string for JSON storage)
  const serializable = {
    ...signed,
    signature: signed.signature ? Buffer.from(signed.signature).toString("base64") : undefined,
  };

  fs.writeFileSync(SIGNED_POLICY_FILE, JSON.stringify(serializable, null, 2));
  console.log(`\n✓ Signed policy saved to: ${SIGNED_POLICY_FILE}`);

  // Summary
  console.log("\n┌──────────────────────────────────────────────┐");
  console.log("│  Policy signed successfully!                 │");
  console.log("├──────────────────────────────────────────────┤");
  console.log(`│  Authority DID: ${authorityIdm.vaultysId.did.slice(0, 30)}...│`);
  console.log("│                                              │");
  console.log("│  To start the MCP server:                    │");
  console.log("│    pnpm start                                │");
  console.log("│                                              │");
  console.log("│  Files generated:                            │");
  console.log(`│    ${SIGNED_POLICY_FILE.padEnd(41)}│`);
  console.log(`│    ${AUTHORITY_PUBLIC_FILE.padEnd(41)}│`);
  console.log(`│    ${AUTHORITY_IDENTITY_FILE.padEnd(41)}│`);
  console.log("└──────────────────────────────────────────────┘");
}

main().catch((err) => {
  console.error("Error:", err);
  process.exit(1);
});
