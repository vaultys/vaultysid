/**
 * VaultysID Web of Trust Sharing Solution
 *
 * This module provides a comprehensive solution for sharing and discovering
 * web of trust relationships across different trust domains using the VaultysID framework.
 */

// Main exports
export { ConnectWithButton } from "./ConnectWithButton";
export { WebOfTrustDiscovery } from "./WebOfTrustDiscovery";

// Type exports
export type { ConnectButtonConfig, TrustInfo, ConnectionResult } from "./ConnectWithButton";

export type { TrustRegistryEntry, TrustPath, DNSWoTRecord, WellKnownVaultysEntry } from "./WebOfTrustDiscovery";

// Re-export example utilities for convenience
export { initializeVaultysID, setupConnectButton, setupWebOfTrustDiscovery, searchAcrossNetworks, findTrustPaths, validateTrustClaim, discoverViaWellKnown, exportTrustNetwork } from "./example";

/**
 * Quick setup function for common use cases
 */
export async function quickSetup(idManager: any, elementId: string, trustedDomains: string[] = [], onConnect?: (contact: any, trustInfo?: any) => void) {
  const { ConnectWithButton } = await import("./ConnectWithButton");

  const button = new ConnectWithButton(idManager, {
    trustedDomains,
    discoveryEnabled: true,
    onConnect,
  });

  button.mount(elementId);
  return button;
}

/**
 * Utility function to format DNS TXT record
 */
export function formatDNSRecord(did: string, publicKey: string, certificate?: string, signature?: string): string {
  let record = `vaultys-wot=v=1;did=${did};pk=${publicKey}`;

  if (certificate) {
    record += `;cert=${certificate}`;
  }

  if (signature) {
    record += `;sig=${signature}`;
  }

  return record;
}

/**
 * Utility function to format well-known endpoint entry
 */
export function formatWellKnownEntry(serverId: string, signature: string, timestamp: number = Date.now(), metadata?: any): any {
  return {
    serverId,
    signature,
    timestamp,
    metadata,
  };
}

/**
 * Helper to validate trust score
 */
export function isHighTrust(trustScore: number, threshold: number = 70): boolean {
  return trustScore >= threshold;
}

/**
 * Helper to get trust level description
 */
export function getTrustLevel(trustScore: number): string {
  if (trustScore >= 90) return "Very High";
  if (trustScore >= 70) return "High";
  if (trustScore >= 50) return "Medium";
  if (trustScore >= 30) return "Low";
  return "Very Low";
}
