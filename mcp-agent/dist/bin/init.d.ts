#!/usr/bin/env node
/**
 * vaultys-mcp-init — Interactive configuration for the MCP agent.
 *
 * Creates or updates configuration in ~/.vaultys-mcp/:
 *   - Server identity (auto-generated if missing)
 *   - Authority identity (auto-generated if missing)
 *   - Signed policy (customizable)
 *
 * Usage:
 *   npx @vaultys/mcp-agent init            # interactive setup
 *   vaultys-mcp-init --hours 48            # 48-hour policy
 *   vaultys-mcp-init --workspace /my/dir   # custom workspace root
 */
export {};
