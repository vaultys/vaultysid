#!/usr/bin/env node
/**
 * SRP Policy Grant CLI
 *
 * Uses the VaultysID Secure Remote Protocol (SRP) to establish a policy
 * agreement between a producer (authority) and an executor (MCP server).
 * This is the canonical VaultysID pattern — both sides exchange certificates,
 * and the policy is cryptographically bound to the SRP metadata.
 *
 * This replaces the manual file-based grant-policy.ts when both parties
 * can communicate over a channel (e.g. in-process via MemoryChannel,
 * or over a network via WebSocket/TCP).
 *
 * Usage:
 *   pnpm srp-grant   # runs a local in-process SRP handshake
 *
 * What happens:
 *   1. Producer and executor identities are loaded or created
 *   2. A MemoryChannel (bidirectional) connects them
 *   3. grantPolicy() and acceptPolicy() run concurrently
 *   4. Both sides store the agreed policy + SRP certificate
 *   5. The executor can now evaluate intents against the stored policy
 */
export {};
