/**
 * Auto-initialization for zero-config startup.
 *
 * When the server starts without a signed policy, this module generates
 * a self-signed default policy so `npx @vaultys/mcp-agent` works immediately.
 *
 * Config directory defaults to ~/.vaultys-mcp/ (overridable via VAULTYS_CONFIG_DIR).
 */
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { ExecutionManager, MemoryStorage, IdManager } from "@vaultys/id";
// ── Config directory ──
export function getConfigDir() {
    return process.env.VAULTYS_CONFIG_DIR ?? path.join(os.homedir(), ".vaultys-mcp");
}
export function ensureConfigDir() {
    const dir = getConfigDir();
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
    return dir;
}
// ── Paths ──
export function configPath(filename) {
    return path.join(getConfigDir(), filename);
}
// ── Default policy ──
const DEFAULT_POLICY_TEMPLATE = {
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
/**
 * Build a policy with resolved workspace path and time bounds.
 */
export function buildPolicy(workspaceRoot, hours = 24 * 365) {
    const now = Date.now();
    // Deep-clone and substitute workspace
    const scopes = {};
    for (const [key, patterns] of Object.entries(DEFAULT_POLICY_TEMPLATE.scopes)) {
        scopes[key] = patterns.map((p) => p.replace(/\{\{WORKSPACE\}\}/g, workspaceRoot));
    }
    return {
        ...DEFAULT_POLICY_TEMPLATE,
        scopes,
        not_before: now,
        not_after: now + hours * 3600_000,
    };
}
/**
 * Load or create a persisted IdManager from a file.
 */
export async function loadOrCreateIdentity(filePath) {
    if (fs.existsSync(filePath)) {
        const data = fs.readFileSync(filePath, "utf-8");
        const store = MemoryStorage().fromString(data);
        const idm = await IdManager.fromStore(store);
        idm.setProtocolVersion(1);
        return { idm, created: false };
    }
    const store = MemoryStorage();
    const idm = await IdManager.fromStore(store);
    idm.setProtocolVersion(1);
    fs.writeFileSync(filePath, store.toString());
    return { idm, created: true };
}
/**
 * Sign and persist a policy. Returns the signed policy and authority IdManager.
 */
export async function signAndPersistPolicy(workspaceRoot, hours) {
    const dir = ensureConfigDir();
    // Load or create authority
    const { idm: authorityIdm, created } = await loadOrCreateIdentity(configPath("authority.secret.json"));
    if (created) {
        console.error(`[VaultysID] Generated authority identity: ${authorityIdm.vaultysId.did}`);
    }
    // Export public key
    const vid = authorityIdm.vaultysId;
    fs.writeFileSync(configPath("authority.identity.json"), JSON.stringify({
        did: vid.did,
        id: Buffer.from(vid.id).toString("base64"),
        fingerprint: vid.fingerprint,
    }, null, 2));
    // Build and sign
    const policy = buildPolicy(workspaceRoot, hours);
    const em = new ExecutionManager(authorityIdm);
    const signedPolicy = await em.signPolicy(policy);
    // Persist (serialize Buffer signature to base64 for JSON)
    const serializable = {
        ...signedPolicy,
        signature: signedPolicy.signature
            ? Buffer.from(signedPolicy.signature).toString("base64")
            : undefined,
    };
    fs.writeFileSync(configPath("policy.signed.json"), JSON.stringify(serializable, null, 2));
    return { signedPolicy, authorityIdm };
}
/**
 * Auto-initialize: load existing policy or generate a default one.
 * Returns all the artifacts needed to start the server.
 */
export async function autoInit(workspaceRoot) {
    const dir = ensureConfigDir();
    // 1. Server identity
    const { idm: serverIdm, created: serverCreated } = await loadOrCreateIdentity(configPath("server.identity.json"));
    if (serverCreated) {
        console.error(`[VaultysID] Generated server identity: ${serverIdm.vaultysId.did}`);
    }
    else {
        console.error(`[VaultysID] Loaded server identity: ${serverIdm.vaultysId.did}`);
    }
    // 2. Policy — try to load existing, otherwise auto-generate
    const policyPath = process.env.POLICY_FILE ?? configPath("policy.signed.json");
    const authorityPath = process.env.AUTHORITY_FILE ?? configPath("authority.identity.json");
    let signedPolicy;
    let authorityDid = "";
    if (fs.existsSync(policyPath)) {
        const raw = JSON.parse(fs.readFileSync(policyPath, "utf-8"));
        if (raw.signature && typeof raw.signature === "string") {
            raw.signature = Buffer.from(raw.signature, "base64");
        }
        signedPolicy = raw;
        console.error(`[VaultysID] Loaded policy (version ${signedPolicy.version})`);
        // Verify if authority key is available
        if (fs.existsSync(authorityPath)) {
            const authRaw = JSON.parse(fs.readFileSync(authorityPath, "utf-8"));
            const { VaultysId } = await import("@vaultys/id");
            const authVid = VaultysId.fromId(Buffer.from(authRaw.id, "base64"));
            const valid = ExecutionManager.verifyPolicy(signedPolicy, authVid);
            if (!valid) {
                console.error(`[VaultysID] WARNING: Policy signature verification FAILED`);
            }
            else {
                console.error(`[VaultysID] Policy signature verified ✓`);
            }
            authorityDid = authVid.did;
        }
        // Check expiry
        const now = Date.now();
        if (signedPolicy.not_after && now > signedPolicy.not_after) {
            console.error(`[VaultysID] Policy expired — regenerating...`);
            const result = await signAndPersistPolicy(workspaceRoot);
            signedPolicy = result.signedPolicy;
            authorityDid = result.authorityIdm.vaultysId.did;
            console.error(`[VaultysID] New policy generated (expires in 1 year)`);
        }
    }
    else {
        // Auto-generate default policy
        console.error(`[VaultysID] No policy found — generating default policy...`);
        const result = await signAndPersistPolicy(workspaceRoot);
        signedPolicy = result.signedPolicy;
        authorityDid = result.authorityIdm.vaultysId.did;
        console.error(`[VaultysID] Default policy generated at ${policyPath}`);
        console.error(`[VaultysID] Run 'vaultys-mcp-init' to customize`);
    }
    return { serverIdm, signedPolicy, authorityDid };
}
