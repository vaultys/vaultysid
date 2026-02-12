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
export {};
