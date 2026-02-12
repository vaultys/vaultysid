#!/usr/bin/env node
/**
 * vaultys-mcp-audit — Verify the cryptographic audit trail.
 *
 * Walks through all signed receipts and verifies broker signatures.
 *
 * Usage:
 *   vaultys-mcp-audit                        # verify all receipts
 *   vaultys-mcp-audit --tamper <job-id>       # tamper then verify (demo)
 *   vaultys-mcp-audit --dir /path/to/audit    # custom audit directory
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { ExecutionManager, IdManager, MemoryStorage } from "@vaultys/id";
import { configPath } from "../src/autoInit.js";
// ── Parse args ──
const args = process.argv.slice(2);
function getArg(name, defaultValue) {
    const idx = args.indexOf(`--${name}`);
    if (idx !== -1 && args[idx + 1])
        return args[idx + 1];
    return defaultValue;
}
const AUDIT_DIR = path.resolve(getArg("dir", "audit"));
const tamperId = getArg("tamper", "");
async function main() {
    console.log("╔══════════════════════════════════════════════════╗");
    console.log("║  VaultysID Audit Trail Verifier                 ║");
    console.log("╚══════════════════════════════════════════════════╝");
    console.log();
    // Load server identity for verification
    let serverVaultysId = null;
    const identityPath = configPath("server.identity.json");
    if (fs.existsSync(identityPath)) {
        const data = fs.readFileSync(identityPath, "utf-8");
        const store = MemoryStorage().fromString(data);
        const idm = await IdManager.fromStore(store);
        if (idm) {
            serverVaultysId = idm.vaultysId;
            console.log(`Server DID: ${serverVaultysId.did}`);
        }
    }
    // Fallback: try local server.identity.json
    if (!serverVaultysId && fs.existsSync("server.identity.json")) {
        const data = fs.readFileSync("server.identity.json", "utf-8");
        const store = MemoryStorage().fromString(data);
        const idm = await IdManager.fromStore(store);
        if (idm) {
            serverVaultysId = idm.vaultysId;
            console.log(`Server DID: ${serverVaultysId.did}`);
        }
    }
    if (!serverVaultysId) {
        console.error("⚠  Cannot load server identity — signature verification disabled");
    }
    console.log();
    // Load receipts
    if (!fs.existsSync(AUDIT_DIR)) {
        console.log("No audit records found. Run some tool calls first!");
        return;
    }
    const files = fs.readdirSync(AUDIT_DIR).filter((f) => f.endsWith(".json")).sort();
    if (files.length === 0) {
        console.log("No audit records found. Run some tool calls first!");
        return;
    }
    console.log(`Found ${files.length} receipt(s)\n`);
    // Optionally tamper
    if (tamperId) {
        const tamperFile = path.join(AUDIT_DIR, `${tamperId}.json`);
        if (fs.existsSync(tamperFile)) {
            const record = JSON.parse(fs.readFileSync(tamperFile, "utf-8"));
            record.receipt.exec.exit_code = 999;
            fs.writeFileSync(tamperFile, JSON.stringify(record, null, 2));
            console.log(`🔧 TAMPERED with receipt ${tamperId} (changed exit_code to 999)\n`);
        }
        else {
            console.error(`⚠  Receipt ${tamperId} not found`);
        }
    }
    let passed = 0;
    let failed = 0;
    let skipped = 0;
    for (const file of files) {
        const filePath = path.join(AUDIT_DIR, file);
        let record;
        try {
            record = JSON.parse(fs.readFileSync(filePath, "utf-8"));
        }
        catch {
            console.log(`  ⚠  ${file}: invalid JSON`);
            skipped++;
            continue;
        }
        const receipt = record.receipt;
        const jobId = record.job_id;
        const decision = record.decision;
        const tool = record.tool;
        if (receipt.broker_signature && typeof receipt.broker_signature === "string") {
            receipt.broker_signature = Buffer.from(receipt.broker_signature, "base64");
        }
        let verified = false;
        let sigStatus = "⏭  no key";
        if (serverVaultysId) {
            verified = ExecutionManager.verifyReceipt(receipt, serverVaultysId);
            sigStatus = verified ? "✅ VALID" : "❌ INVALID";
            if (verified)
                passed++;
            else
                failed++;
        }
        else {
            skipped++;
        }
        const decisionIcon = decision === "allow" ? "🟢" : "🔴";
        console.log(`  ${sigStatus}  ${decisionIcon} ${tool.padEnd(16)}  ${jobId}  ${record.timestamp}`);
        if (!verified && serverVaultysId) {
            console.log(`           ⚠  Signature verification FAILED — possible tampering!`);
        }
    }
    console.log();
    console.log("─".repeat(52));
    console.log(`  Results: ${passed} verified, ${failed} FAILED, ${skipped} skipped`);
    if (failed > 0) {
        console.log();
        console.log("  ⚠  TAMPERING DETECTED in one or more receipts!");
    }
    else if (passed > 0) {
        console.log();
        console.log("  ✅ All receipts verified — audit trail is intact.");
    }
    console.log();
}
main().catch((err) => {
    console.error("Error:", err);
    process.exit(1);
});
