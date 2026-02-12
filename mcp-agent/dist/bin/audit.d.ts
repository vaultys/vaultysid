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
export {};
