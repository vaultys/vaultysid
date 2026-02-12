/**
 * Audit verification MCP tool — lets Claude verify the cryptographic audit trail.
 *
 * Tool:
 *   verify_audit  — verify all signed receipts, report valid/invalid/tampered
 */
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { IdManager } from "@vaultys/id";
export declare function registerAuditTool(server: McpServer, serverIdManager: IdManager): void;
