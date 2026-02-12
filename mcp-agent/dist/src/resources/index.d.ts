/**
 * MCP Resources — expose policy, identity, and audit trail as readable resources.
 *
 * Resources:
 *   vaultys://policy/current    — the active signed policy (JSON)
 *   vaultys://identity/server   — the server's VaultysID DID + public key info
 *   vaultys://receipts/list     — summary of all signed receipts
 *   vaultys://receipt/{id}      — individual receipt (verifiable)
 */
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { PolicyBundle } from "@vaultys/id";
import type { IdManager } from "@vaultys/id";
export declare function setResourceAuditDir(dir: string): void;
export declare function registerResources(server: McpServer, serverIdManager: IdManager, signedPolicy: PolicyBundle): void;
