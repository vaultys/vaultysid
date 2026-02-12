/**
 * Filesystem MCP tools — read_file, write_file, list_directory
 *
 * All operations are sandboxed to the workspace root via policy evaluation.
 */
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { createPolicyMiddleware } from "../policyMiddleware.js";
type Middleware = ReturnType<typeof createPolicyMiddleware>;
export declare function registerFilesystemTools(server: McpServer, middleware: Middleware, workspaceRoot: string): void;
export {};
