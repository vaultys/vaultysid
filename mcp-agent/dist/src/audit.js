#!/usr/bin/env node
/**
 * Audit Verify CLI
 *
 * Walks through all signed receipts in ./audit/ and verifies each one.
 * Also detects tampering by re-verifying broker signatures.
 *
 * Usage:
 *   pnpm audit                      # verify all receipts
 *   pnpm audit -- --tamper <id>     # tamper with a receipt then verify (demo)
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { ExecutionManager, IdManager, MemoryStorage } from "@vaultys/id";
const AUDIT_DIR = path.resolve("audit");
const IDENTITY_FILE = "server.identity.json";
function loadServerPublicKey() {
    if (!fs.existsSync(IDENTITY_FILE)) {
        console.error("⚠ No server identity found. Cannot verify receipts.");
        return null;
    }
    // We need the server's serialized identity to extract the public key.
    // For verification we only need the public key, but the serialized format has it.
    // We'll load it as a full IdManager to get the VaultysId.
    return null; // Will use async version
}
async function main() {
    const args = process.argv.slice(2);
    const tamperIdx = args.indexOf("--tamper");
    const tamperId = tamperIdx !== -1 ? args[tamperIdx + 1] : null;
    console.log("╔══════════════════════════════════════════════════╗");
    console.log("║  VaultysID Audit Trail Verifier                 ║");
    console.log("╚══════════════════════════════════════════════════╝");
    console.log();
    // Load server identity for signature verification
    let serverVaultysId = null;
    if (fs.existsSync(IDENTITY_FILE)) {
        // Read the serialized identity to extract the VaultysId
        const data = fs.readFileSync(IDENTITY_FILE, "utf-8");
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
    // Load all receipts
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
    // Optionally tamper with a receipt for demo purposes
    if (tamperId) {
        const tamperFile = path.join(AUDIT_DIR, `${tamperId}.json`);
        if (fs.existsSync(tamperFile)) {
            const record = JSON.parse(fs.readFileSync(tamperFile, "utf-8"));
            record.receipt.exec.exit_code = 999; // Tamper!
            fs.writeFileSync(tamperFile, JSON.stringify(record, null, 2));
            console.log(`🔧 TAMPERED with receipt ${tamperId} (changed exit_code to 999)\n`);
        }
        else {
            console.error(`⚠  Receipt ${tamperId} not found for tampering`);
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
        // Restore Buffer types for signature
        if (receipt.broker_signature) {
            if (typeof receipt.broker_signature === "string") {
                receipt.broker_signature = Buffer.from(receipt.broker_signature, "base64");
            }
            else if (typeof receipt.broker_signature === "object" && receipt.broker_signature.data) {
                receipt.broker_signature = Buffer.from(receipt.broker_signature.data);
            }
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
        console.log("  ⚠  The audit trail has been compromised.");
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
