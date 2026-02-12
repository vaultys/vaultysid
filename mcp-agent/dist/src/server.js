#!/usr/bin/env node
/**
 * VaultysID Policy-Enforced MCP Server
 *
 * Stdio transport — plug directly into Claude Desktop, Cursor, or any MCP client.
 *
 * Zero-config: just run `npx @vaultys/mcp-agent` — a default policy is
 * auto-generated on first start. Customize with `vaultys-mcp-init`.
 *
 * Every tool call goes through:
 *   tool invocation → capability mapping → policy evaluation → execute/deny → signed receipt
 *
 * Environment variables:
 *   WORKSPACE_ROOT      — working directory for file/shell operations (default: cwd)
 *   POLICY_FILE         — path to a custom signed policy file
 *   AUTHORITY_FILE      — path to the authority identity export
 *   VAULTYS_CONFIG_DIR  — config directory (default: ~/.vaultys-mcp)
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { autoInit, getConfigDir } from "./autoInit.js";
import { createPolicyMiddleware } from "./policyMiddleware.js";
import { registerFilesystemTools } from "./tools/filesystem.js";
import { registerShellTool } from "./tools/shell.js";
import { registerNetworkTool } from "./tools/network.js";
import { registerAuditTool } from "./tools/audit.js";
import { registerResources } from "./resources/index.js";
// ── Configuration ──
const WORKSPACE_ROOT = path.resolve(process.env.WORKSPACE_ROOT ?? process.cwd());
// ── Main ──
async function main() {
    console.error(`[VaultysID] Config dir: ${getConfigDir()}`);
    // 1. Auto-initialize (identity + policy — generates defaults on first run)
    const { serverIdm, signedPolicy, authorityDid } = await autoInit(WORKSPACE_ROOT);
    // 2. Check time bounds
    const now = Date.now();
    if (signedPolicy.not_before && now < signedPolicy.not_before) {
        console.error(`[VaultysID] ERROR: Policy is not yet valid`);
        process.exit(1);
    }
    if (signedPolicy.not_after) {
        const remaining = Math.round((signedPolicy.not_after - now) / 60000);
        console.error(`[VaultysID] Policy expires in ${remaining} minutes`);
    }
    // 3. Ensure workspace exists
    if (!fs.existsSync(WORKSPACE_ROOT)) {
        fs.mkdirSync(WORKSPACE_ROOT, { recursive: true });
    }
    console.error(`[VaultysID] Workspace: ${WORKSPACE_ROOT}`);
    // 4. Create policy middleware
    const middleware = createPolicyMiddleware({
        serverIdManager: serverIdm,
        signedPolicy,
        workspaceRoot: WORKSPACE_ROOT,
    });
    // 5. Create MCP Server
    const mcpServer = new McpServer({
        name: "vaultys-mcp-agent",
        version: "0.1.0",
    }, {
        capabilities: {
            resources: {},
            tools: {},
        },
    });
    // 6. Register tools (all wrapped by policy middleware)
    registerFilesystemTools(mcpServer, middleware, WORKSPACE_ROOT);
    registerShellTool(mcpServer, middleware, WORKSPACE_ROOT);
    registerNetworkTool(mcpServer, middleware);
    registerAuditTool(mcpServer, serverIdm);
    // 7. Register resources (audit trail, policy, identity)
    registerResources(mcpServer, serverIdm, signedPolicy);
    // 8. Connect via stdio transport
    const transport = new StdioServerTransport();
    await mcpServer.connect(transport);
    console.error(`[VaultysID] MCP server running on stdio`);
    console.error(`[VaultysID] Server DID: ${serverIdm.vaultysId.did}`);
    if (authorityDid) {
        console.error(`[VaultysID] Authority DID: ${authorityDid}`);
    }
    console.error(`[VaultysID] Tools: read_file, write_file, list_directory, run_command, fetch_url`);
    console.error(`[VaultysID] Resources: vaultys://policy/current, vaultys://identity/server, vaultys://receipts/list`);
}
main().catch((err) => {
    console.error("Fatal error:", err);
    process.exit(1);
});
