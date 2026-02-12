/**
 * MCP Resources — expose policy, identity, and audit trail as readable resources.
 *
 * Resources:
 *   vaultys://policy/current    — the active signed policy (JSON)
 *   vaultys://identity/server   — the server's VaultysID DID + public key info
 *   vaultys://receipts/list     — summary of all signed receipts
 *   vaultys://receipt/{id}      — individual receipt (verifiable)
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { PolicyBundle } from "@vaultys/id";
import type { IdManager } from "@vaultys/id";

const AUDIT_DIR = path.resolve("audit");

export function registerResources(
  server: McpServer,
  serverIdManager: IdManager,
  signedPolicy: PolicyBundle,
) {
  // ── Current Policy ──
  server.resource(
    "current-policy",
    "vaultys://policy/current",
    { mimeType: "application/json", description: "The active signed policy bundle" },
    async () => {
      const { signature, ...policyWithoutSig } = signedPolicy;
      return {
        contents: [{
          uri: "vaultys://policy/current",
          mimeType: "application/json",
          text: JSON.stringify({
            ...policyWithoutSig,
            signature_present: !!signature,
            signature_length: signature?.length ?? 0,
          }, null, 2),
        }],
      };
    },
  );

  // ── Server Identity ──
  server.resource(
    "server-identity",
    "vaultys://identity/server",
    { mimeType: "application/json", description: "The server's VaultysID (DID + key info)" },
    async () => {
      const vid = serverIdManager.vaultysId;
      return {
        contents: [{
          uri: "vaultys://identity/server",
          mimeType: "application/json",
          text: JSON.stringify({
            did: vid.did,
            fingerprint: vid.fingerprint,
            type: vid.type === 0 ? "person" : "machine",
            algorithm: vid.keyManager.constructor.name,
          }, null, 2),
        }],
      };
    },
  );

  // ── Receipt List ──
  server.resource(
    "receipts-list",
    "vaultys://receipts/list",
    { mimeType: "application/json", description: "Summary of all signed execution receipts" },
    async () => {
      const receipts = listReceiptFiles();
      return {
        contents: [{
          uri: "vaultys://receipts/list",
          mimeType: "application/json",
          text: JSON.stringify({
            total: receipts.length,
            receipts: receipts.map((r) => ({
              job_id: r.job_id,
              timestamp: r.timestamp,
              tool: r.tool,
              decision: r.decision,
            })),
          }, null, 2),
        }],
      };
    },
  );
}

// ── Helpers ──

interface ReceiptRecord {
  job_id: string;
  timestamp: string;
  tool: string;
  decision: string;
  receipt: unknown;
}

function listReceiptFiles(): ReceiptRecord[] {
  if (!fs.existsSync(AUDIT_DIR)) return [];
  return fs.readdirSync(AUDIT_DIR)
    .filter((f) => f.endsWith(".json"))
    .map((f) => {
      try {
        return JSON.parse(fs.readFileSync(path.join(AUDIT_DIR, f), "utf-8")) as ReceiptRecord;
      } catch {
        return null;
      }
    })
    .filter((r): r is ReceiptRecord => r !== null)
    .sort((a, b) => b.timestamp.localeCompare(a.timestamp));
}
