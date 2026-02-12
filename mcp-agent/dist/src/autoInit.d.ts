/**
 * Auto-initialization for zero-config startup.
 *
 * When the server starts without a signed policy, this module generates
 * a self-signed default policy so `npx @vaultys/mcp-agent` works immediately.
 *
 * Config directory defaults to ~/.vaultys-mcp/ (overridable via VAULTYS_CONFIG_DIR).
 */
import { IdManager } from "@vaultys/id";
import type { PolicyBundle } from "@vaultys/id";
export declare function getConfigDir(): string;
export declare function ensureConfigDir(): string;
export declare function configPath(filename: string): string;
/**
 * Build a policy with resolved workspace path and time bounds.
 */
export declare function buildPolicy(workspaceRoot: string, hours?: number): Omit<PolicyBundle, "signature">;
/**
 * Load or create a persisted IdManager from a file.
 */
export declare function loadOrCreateIdentity(filePath: string): Promise<{
    idm: IdManager;
    created: boolean;
}>;
/**
 * Sign and persist a policy. Returns the signed policy and authority IdManager.
 */
export declare function signAndPersistPolicy(workspaceRoot: string, hours?: number): Promise<{
    signedPolicy: PolicyBundle;
    authorityIdm: IdManager;
}>;
/**
 * Auto-initialize: load existing policy or generate a default one.
 * Returns all the artifacts needed to start the server.
 */
export declare function autoInit(workspaceRoot: string): Promise<{
    serverIdm: IdManager;
    signedPolicy: PolicyBundle;
    authorityDid: string;
}>;
