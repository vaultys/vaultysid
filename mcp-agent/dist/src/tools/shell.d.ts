/**
 * Shell MCP tool — run_command
 *
 * Executes shell commands with policy enforcement.
 * Shell metacharacters are blocked by the `no_shell_features` constraint.
 */
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { createPolicyMiddleware } from "../policyMiddleware.js";
type Middleware = ReturnType<typeof createPolicyMiddleware>;
export declare function registerShellTool(server: McpServer, middleware: Middleware, workspaceRoot: string): void;
export {};
