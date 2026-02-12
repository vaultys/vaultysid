#!/usr/bin/env node
/**
 * vaultys-mcp-agent — Start the policy-enforced MCP server.
 *
 * Usage:
 *   npx @vaultys/mcp-agent                           # zero-config, uses cwd
 *   WORKSPACE_ROOT=/my/project npx @vaultys/mcp-agent # custom workspace
 */

import "../src/server.js";
