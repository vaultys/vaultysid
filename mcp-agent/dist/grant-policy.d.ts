#!/usr/bin/env node
/**
 * Grant Policy CLI
 *
 * Creates an authority identity and signs a policy bundle.
 * Outputs:
 *   - policy.signed.json       — the signed policy (loaded by the MCP server)
 *   - authority.identity.json  — the authority's public key (for verification)
 *   - authority.secret.json    — the authority's full identity (keep safe!)
 *
 * Usage:
 *   pnpm grant-policy                          # uses policy.example.json, 24h validity
 *   pnpm grant-policy -- --policy custom.json  # custom policy file
 *   pnpm grant-policy -- --hours 2             # 2-hour validity window
 */
export {};
