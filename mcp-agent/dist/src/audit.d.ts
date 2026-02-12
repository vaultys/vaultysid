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
export {};
