#!/usr/bin/env node
/**
 * vaultys-mcp-grant — Sign a custom policy for the MCP agent.
 *
 * Usage:
 *   vaultys-mcp-grant                                              # default policy, 1 year
 *   vaultys-mcp-grant --policy custom.json --hours 2               # custom policy, 2 hours
 *   vaultys-mcp-grant --workspace /my/project --hours 48           # custom workspace
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { ensureConfigDir, configPath, loadOrCreateIdentity, } from "../src/autoInit.js";
import { ExecutionManager } from "@vaultys/id";
// ── Parse args ──
const args = process.argv.slice(2);
function getArg(name, defaultValue) {
    const idx = args.indexOf(`--${name}`);
    if (idx !== -1 && args[idx + 1])
        return args[idx + 1];
    return defaultValue;
}
const policyFile = getArg("policy", "");
const hours = parseInt(getArg("hours", String(24 * 365)), 10);
const workspaceRoot = path.resolve(getArg("workspace", process.cwd()));
async function main() {
    console.log("╔══════════════════════════════════════════════════╗");
    console.log("║  VaultysID MCP Agent — Grant Policy             ║");
    console.log("╚══════════════════════════════════════════════════╝");
    console.log();
    ensureConfigDir();
    // 1. Load or create authority
    const { idm: authorityIdm, created } = await loadOrCreateIdentity(configPath("authority.secret.json"));
    if (created) {
        console.log(`✓ Generated authority identity: ${authorityIdm.vaultysId.did}`);
    }
    else {
        console.log(`✓ Loaded authority identity: ${authorityIdm.vaultysId.did}`);
    }
    // Export public identity
    const vid = authorityIdm.vaultysId;
    fs.writeFileSync(configPath("authority.identity.json"), JSON.stringify({
        did: vid.did,
        id: Buffer.from(vid.id).toString("base64"),
        fingerprint: vid.fingerprint,
    }, null, 2));
    // 2. Load policy template
    let policyTemplate;
    if (policyFile && fs.existsSync(policyFile)) {
        policyTemplate = JSON.parse(fs.readFileSync(policyFile, "utf-8"));
        console.log(`✓ Loaded custom policy: ${policyFile}`);
    }
    else {
        // Use built-in default
        policyTemplate = {
            version: "1.0",
            scopes: {
                "fs.read": ["{{WORKSPACE}}/**"],
                "fs.write": ["{{WORKSPACE}}/**"],
                "fs.list": ["{{WORKSPACE}}/**"],
                "proc.exec": ["ls", "cat", "echo", "wc", "head", "tail", "grep", "find", "pwd", "date", "whoami"],
                "net.egress.http": ["*"],
            },
            denied: ["secrets.*", "pkg.system", "proc.privilege"],
            constraints: {
                max_runtime: 300,
                no_shell_features: true,
            },
        };
        console.log("✓ Using default policy template");
    }
    // 3. Substitute {{WORKSPACE}} placeholder
    if (policyTemplate.scopes && typeof policyTemplate.scopes === "object") {
        const scopes = policyTemplate.scopes;
        for (const [key, patterns] of Object.entries(scopes)) {
            if (Array.isArray(patterns)) {
                scopes[key] = patterns.map((p) => p.replace(/\{\{WORKSPACE\}\}/g, workspaceRoot));
            }
        }
    }
    // 4. Add time bounds
    const now = Date.now();
    const policy = {
        ...policyTemplate,
        not_before: now,
        not_after: now + hours * 3600_000,
    };
    console.log(`  Workspace: ${workspaceRoot}`);
    console.log(`  Valid from: ${new Date(now).toISOString()}`);
    console.log(`  Expires:    ${new Date(now + hours * 3600_000).toISOString()}`);
    console.log(`  Duration:   ${hours} hours`);
    // 5. Sign
    const em = new ExecutionManager(authorityIdm);
    const signed = await em.signPolicy(policy);
    // 6. Persist
    const serializable = {
        ...signed,
        signature: signed.signature
            ? Buffer.from(signed.signature).toString("base64")
            : undefined,
    };
    fs.writeFileSync(configPath("policy.signed.json"), JSON.stringify(serializable, null, 2));
    console.log();
    console.log(`✓ Signed policy saved to: ${configPath("policy.signed.json")}`);
    console.log();
    console.log("Run 'npx @vaultys/mcp-agent' to start the server with this policy.");
}
main().catch((err) => {
    console.error("Error:", err);
    process.exit(1);
});
