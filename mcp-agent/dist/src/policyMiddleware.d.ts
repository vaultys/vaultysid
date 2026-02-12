/**
 * Policy Middleware — wraps every MCP tool call through ExecutionManager.
 *
 * For each tool invocation the middleware:
 *   1. Maps the MCP tool name + arguments → taxonomy capability strings
 *   2. Creates and signs an ExecutionIntent via the server's IdManager
 *   3. Evaluates the intent against the loaded signed PolicyBundle
 *   4. If allowed, executes the real handler and signs a receipt
 *   5. If denied, returns a denial message and signs a deny receipt
 *
 * All receipts are persisted to ./audit/ as JSON files.
 */
import { ExecutionManager } from "@vaultys/id";
import type { PolicyBundle, SignedReceipt } from "@vaultys/id";
import type { IdManager } from "@vaultys/id";
export interface CapabilityMapping {
    /** Taxonomy prefix, e.g. "fs.read" */
    capability: string;
    /** Extract the scope string from the tool arguments. workspaceRoot is provided for path resolution. */
    extractScope: (args: Record<string, unknown>, workspaceRoot?: string) => string;
}
/**
 * Default mappings from MCP tool names to taxonomy capabilities.
 *
 * Scopes must match the format used in the policy's scope patterns.
 * For filesystem tools: full resolved paths (e.g. "/workspace/src/file.ts")
 * For process tools: the binary name (e.g. "ls", "npm")
 * For network tools: the hostname (e.g. "api.example.com")
 *
 * The `workspaceRoot` parameter is passed to `extractScope` so that filesystem
 * tools can resolve relative paths to absolute paths matching the policy globs.
 */
export declare const DEFAULT_TOOL_MAPPINGS: Record<string, CapabilityMapping>;
export declare function setAuditDir(dir: string): void;
export interface PolicyMiddlewareOptions {
    serverIdManager: IdManager;
    signedPolicy: PolicyBundle;
    toolMappings?: Record<string, CapabilityMapping>;
    workspaceRoot?: string;
    auditDir?: string;
}
export interface ToolCallResult {
    decision: "allow" | "deny";
    content: Array<{
        type: "text";
        text: string;
    }>;
    receipt?: SignedReceipt;
    jobId?: string;
}
/**
 * Create policy-enforced middleware that wraps MCP tool handlers.
 */
export declare function createPolicyMiddleware(options: PolicyMiddlewareOptions): {
    enforce: (toolName: string, args: Record<string, unknown>, handler: () => Promise<string>) => Promise<ToolCallResult>;
    em: ExecutionManager;
};
