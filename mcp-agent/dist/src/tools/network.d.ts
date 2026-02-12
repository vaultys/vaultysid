/**
 * Network MCP tool — fetch_url
 *
 * Fetches content from a URL with policy enforcement on the hostname.
 */
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { createPolicyMiddleware } from "../policyMiddleware.js";
type Middleware = ReturnType<typeof createPolicyMiddleware>;
export declare function registerNetworkTool(server: McpServer, middleware: Middleware): void;
export {};
