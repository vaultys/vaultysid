/**
 * Audit verification MCP tool — lets Claude verify the cryptographic audit trail.
 *
 * Tool:
 *   verify_audit  — verify all signed receipts, report valid/invalid/tampered
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { z } from "zod";
import { ExecutionManager } from "@vaultys/id";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { IdManager } from "@vaultys/id";
import type { SignedReceipt } from "@vaultys/id";

const AUDIT_DIR = path.resolve("audit");

interface AuditRecord {
  job_id: string;
  timestamp: string;
  tool: string;
  decision: string;
  args?: Record<string, unknown>;
  allowed_caps?: string[];
  denied_caps?: string[];
  receipt: SignedReceipt;
}

function restoreSignature(receipt: SignedReceipt): void {
  if (receipt.broker_signature) {
    if (typeof receipt.broker_signature === "string") {
      receipt.broker_signature = Buffer.from(receipt.broker_signature, "base64") as any;
    } else if (typeof receipt.broker_signature === "object" && (receipt.broker_signature as any).data) {
      receipt.broker_signature = Buffer.from((receipt.broker_signature as any).data) as any;
    }
  }
}

export function registerAuditTool(
  server: McpServer,
  serverIdManager: IdManager,
) {
  server.tool(
    "verify_audit",
    "Verify the cryptographic audit trail. Checks all signed receipts for tampering. Returns verification results for each receipt.",
    {
      limit: z.number().optional().describe("Maximum number of recent receipts to verify (default: all)"),
    },
    async (args) => {
      const serverVid = serverIdManager.vaultysId;

      if (!fs.existsSync(AUDIT_DIR)) {
        return {
          content: [{ type: "text" as const, text: "No audit directory found. No tool calls have been recorded yet." }],
        };
      }

      const files = fs.readdirSync(AUDIT_DIR)
        .filter((f) => f.endsWith(".json"))
        .sort();

      if (files.length === 0) {
        return {
          content: [{ type: "text" as const, text: "No audit receipts found. No tool calls have been recorded yet." }],
        };
      }

      const limit = args.limit ?? files.length;
      const toVerify = files.slice(-limit); // most recent N

      let passed = 0;
      let failed = 0;
      let errors = 0;
      const results: Array<{
        job_id: string;
        timestamp: string;
        tool: string;
        decision: string;
        verified: boolean | "error";
      }> = [];

      for (const file of toVerify) {
        const filePath = path.join(AUDIT_DIR, file);
        let record: AuditRecord;

        try {
          record = JSON.parse(fs.readFileSync(filePath, "utf-8"));
        } catch {
          errors++;
          results.push({
            job_id: file.replace(".json", ""),
            timestamp: "?",
            tool: "?",
            decision: "?",
            verified: "error",
          });
          continue;
        }

        restoreSignature(record.receipt);

        let verified = false;
        try {
          verified = ExecutionManager.verifyReceipt(record.receipt, serverVid);
        } catch {
          verified = false;
        }

        if (verified) passed++;
        else failed++;

        results.push({
          job_id: record.job_id,
          timestamp: record.timestamp,
          tool: record.tool,
          decision: record.decision,
          verified,
        });
      }

      const summary = {
        total: files.length,
        verified_count: toVerify.length,
        passed,
        failed,
        errors,
        integrity: failed === 0 && errors === 0 ? "INTACT" : "COMPROMISED",
        server_did: serverVid.did,
        results,
      };

      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify(summary, null, 2),
        }],
      };
    },
  );
}
