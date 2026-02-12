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
import * as path from "node:path";
import { ensureConfigDir, loadOrCreateIdentity, configPath, signAndPersistPolicy, } from "../src/autoInit.js";
// ── Parse args ──
const args = process.argv.slice(2);
function getArg(name, defaultValue) {
    const idx = args.indexOf(`--${name}`);
    if (idx !== -1 && args[idx + 1])
        return args[idx + 1];
    return defaultValue;
}
const hours = parseInt(getArg("hours", String(24 * 365)), 10);
const workspaceRoot = path.resolve(getArg("workspace", process.cwd()));
async function main() {
    console.log("╔══════════════════════════════════════════════════╗");
    console.log("║  VaultysID MCP Agent — Setup                    ║");
    console.log("╚══════════════════════════════════════════════════╝");
    console.log();
    const dir = ensureConfigDir();
    console.log(`Config directory: ${dir}`);
    console.log();
    // 1. Server identity
    const { idm: serverIdm, created: serverCreated } = await loadOrCreateIdentity(configPath("server.identity.json"));
    if (serverCreated) {
        console.log(`✓ Generated server identity: ${serverIdm.vaultysId.did}`);
    }
    else {
        console.log(`✓ Server identity exists: ${serverIdm.vaultysId.did}`);
    }
    // 2. Authority + Policy
    const { signedPolicy, authorityIdm } = await signAndPersistPolicy(workspaceRoot, hours);
    console.log(`✓ Authority DID: ${authorityIdm.vaultysId.did}`);
    console.log(`✓ Policy signed (${hours} hours validity)`);
    console.log(`  Workspace: ${workspaceRoot}`);
    if (signedPolicy.not_before) {
        console.log(`  Valid from: ${new Date(signedPolicy.not_before).toISOString()}`);
    }
    if (signedPolicy.not_after) {
        console.log(`  Expires:    ${new Date(signedPolicy.not_after).toISOString()}`);
    }
    console.log();
    console.log("┌──────────────────────────────────────────────────┐");
    console.log("│  Setup complete!                                 │");
    console.log("├──────────────────────────────────────────────────┤");
    console.log("│                                                  │");
    console.log("│  Add to Claude Desktop config:                   │");
    console.log("│                                                  │");
    console.log('│  "mcpServers": {                                 │');
    console.log('│    "vaultys-agent": {                            │');
    console.log('│      "command": "npx",                           │');
    console.log('│      "args": ["@vaultys/mcp-agent"]              │');
    console.log("│    }                                             │");
    console.log("│  }                                               │");
    console.log("│                                                  │");
    console.log("│  Config file location (macOS):                   │");
    console.log("│  ~/Library/Application Support/Claude/           │");
    console.log("│    claude_desktop_config.json                    │");
    console.log("│                                                  │");
    console.log("└──────────────────────────────────────────────────┘");
}
main().catch((err) => {
    console.error("Error:", err);
    process.exit(1);
});
