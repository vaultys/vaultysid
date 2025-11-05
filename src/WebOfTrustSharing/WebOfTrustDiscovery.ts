import { Buffer } from "buffer/";
import { decode, encode } from "@msgpack/msgpack";
import VaultysId from "../VaultysId";
import Challenger, { ChallengeType } from "../Challenger";
import { hash, verify } from "../crypto";

/**
 * Web of Trust Registry Entry
 * Represents a trust anchor that can be discovered via DNS or other mechanisms
 */
export interface TrustRegistryEntry {
  did: string;
  publicKey: Buffer;
  domain: string;
  certificateChain?: Buffer[];
  metadata?: {
    organizationName?: string;
    trustLevel?: number;
    validFrom?: number;
    validUntil?: number;
    services?: string[];
  };
}

/**
 * Trust Path represents a chain of trust from a source to a target
 */
export interface TrustPath {
  sourceDid: string;
  targetDid: string;
  path: string[];
  certificates: Buffer[];
  trustScore: number;
}

/**
 * DNS TXT Record format for VaultysID Web of Trust
 * Format: "vaultys-wot=v=1;did=<did>;pk=<base64_public_key>;cert=<base64_cert>"
 */
export interface DNSWoTRecord {
  version: number;
  did: string;
  publicKey: string;
  certificate?: string;
  signature?: string;
}

/**
 * Well-known endpoint response format
 */
export interface WellKnownVaultysEntry {
  serverId: string;
  signature: string;
  timestamp: number;
  metadata?: {
    organizationName?: string;
    services?: string[];
  };
}

/**
 * Web of Trust Discovery Service
 * Enables discovery and validation of trust relationships across different trust domains
 */
export class WebOfTrustDiscovery {
  private trustRegistries: Map<string, TrustRegistryEntry>;
  private dnsCacheTimeout: number = 3600000; // 1 hour
  private dnsCache: Map<string, { record: DNSWoTRecord; timestamp: number }>;
  private wellKnownCache: Map<string, { entry: WellKnownVaultysEntry; timestamp: number }>;
  private trustedDomains: Set<string>;

  constructor(trustedDomains: string[] = []) {
    this.trustRegistries = new Map();
    this.dnsCache = new Map();
    this.wellKnownCache = new Map();
    this.trustedDomains = new Set(trustedDomains);
  }

  /**
   * Add a trusted domain for DNS-based discovery
   */
  addTrustedDomain(domain: string): void {
    this.trustedDomains.add(domain);
  }

  /**
   * Remove a trusted domain
   */
  removeTrustedDomain(domain: string): void {
    this.trustedDomains.delete(domain);
  }

  /**
   * Query DNS TXT records for VaultysID Web of Trust entries
   */
  async queryDNSWoTRecord(domain: string): Promise<DNSWoTRecord | null> {
    // Check cache first
    const cached = this.dnsCache.get(domain);
    if (cached && Date.now() - cached.timestamp < this.dnsCacheTimeout) {
      return cached.record;
    }

    try {
      // In Node.js environment
      if (typeof window === "undefined") {
        const dns = await import("dns").then((m) => m.promises);
        const records = await dns.resolveTxt(`_vaultys-wot.${domain}`);

        for (const record of records) {
          const txtData = record.join("");
          if (txtData.startsWith("vaultys-wot=")) {
            const parsedRecord = this.parseDNSRecord(txtData);
            if (parsedRecord) {
              this.dnsCache.set(domain, {
                record: parsedRecord,
                timestamp: Date.now(),
              });
              return parsedRecord;
            }
          }
        }
      } else {
        // In browser environment, use DoH (DNS over HTTPS)
        const response = await fetch(`https://cloudflare-dns.com/dns-query?name=_vaultys-wot.${domain}&type=TXT`, {
          headers: { Accept: "application/dns-json" },
        });

        if (response.ok) {
          const data = await response.json();
          if (data.Answer) {
            for (const answer of data.Answer) {
              if (answer.type === 16) {
                // TXT record
                const txtData = answer.data.replace(/"/g, "");
                if (txtData.startsWith("vaultys-wot=")) {
                  const parsedRecord = this.parseDNSRecord(txtData);
                  if (parsedRecord) {
                    this.dnsCache.set(domain, {
                      record: parsedRecord,
                      timestamp: Date.now(),
                    });
                    return parsedRecord;
                  }
                }
              }
            }
          }
        }
      }
    } catch (error) {
      console.error(`Failed to query DNS for domain ${domain}:`, error);
    }

    return null;
  }

  /**
   * Parse DNS TXT record format
   */
  private parseDNSRecord(txtData: string): DNSWoTRecord | null {
    try {
      const content = txtData.replace("vaultys-wot=", "");
      const params = new Map<string, string>();

      content.split(";").forEach((param) => {
        const [key, value] = param.split("=");
        if (key && value) {
          params.set(key.trim(), value.trim());
        }
      });

      if (!params.has("v") || !params.has("did") || !params.has("pk")) {
        return null;
      }

      return {
        version: parseInt(params.get("v")!),
        did: params.get("did")!,
        publicKey: params.get("pk")!,
        certificate: params.get("cert"),
        signature: params.get("sig"),
      };
    } catch (error) {
      console.error("Failed to parse DNS record:", error);
      return null;
    }
  }

  /**
   * Query well-known endpoint for VaultysID identity
   */
  async queryWellKnownEndpoint(domain: string): Promise<WellKnownVaultysEntry | null> {
    // Check cache first
    const cached = this.wellKnownCache.get(domain);
    if (cached && Date.now() - cached.timestamp < this.dnsCacheTimeout) {
      return cached.entry;
    }

    try {
      const urls = [`https://${domain}/.well-known/vaultys.json`, `http://${domain}/.well-known/vaultys.json`];

      for (const url of urls) {
        try {
          const response = await fetch(url, {
            method: "GET",
            headers: { Accept: "application/json" },
            signal: AbortSignal.timeout(5000), // 5 second timeout
          });

          if (response.ok) {
            const data = await response.json();

            // Validate the response structure
            if (data.serverId && data.signature && data.timestamp) {
              const entry: WellKnownVaultysEntry = {
                serverId: data.serverId,
                signature: data.signature,
                timestamp: data.timestamp,
                metadata: data.metadata,
              };

              // Cache the result
              this.wellKnownCache.set(domain, {
                entry,
                timestamp: Date.now(),
              });

              return entry;
            }
          }
        } catch (error) {
          // Try next URL if this one fails
          continue;
        }
      }
    } catch (error) {
      console.error(`Failed to query well-known endpoint for domain ${domain}:`, error);
    }

    return null;
  }

  /**
   * Verify well-known endpoint signature
   */
  private async verifyWellKnownSignature(entry: WellKnownVaultysEntry): Promise<boolean> {
    try {
      const vaultysId = VaultysId.fromId(entry.serverId, undefined, "base64");
      const signatureBuffer = Buffer.from(entry.signature, "base64");

      // Create the data that was signed (serverId + timestamp)
      const dataToVerify = Buffer.concat([Buffer.from(entry.serverId), Buffer.from(entry.timestamp.toString())]);

      // Verify the signature
      return await verify(vaultysId.keyManager.signer.publicKey, dataToVerify, signatureBuffer);
    } catch (error) {
      console.error("Failed to verify well-known signature:", error);
      return false;
    }
  }

  /**
   * Discover trust anchors from a domain using multiple methods
   */
  async discoverTrustAnchors(domain: string): Promise<TrustRegistryEntry | null> {
    if (!this.trustedDomains.has(domain)) {
      console.warn(`Domain ${domain} is not in trusted domains list`);
      return null;
    }

    // Try well-known endpoint first
    const wellKnownEntry = await this.queryWellKnownEndpoint(domain);
    if (wellKnownEntry) {
      try {
        // Verify the signature
        const isValid = await this.verifyWellKnownSignature(wellKnownEntry);
        if (!isValid) {
          console.error("Invalid signature for well-known entry");
        } else {
          // Create trust registry entry from well-known data
          const vaultysId = VaultysId.fromId(wellKnownEntry.serverId, undefined, "base64");

          const entry: TrustRegistryEntry = {
            did: vaultysId.did,
            publicKey: vaultysId.keyManager.signer.publicKey,
            domain,
            metadata: {
              organizationName: wellKnownEntry.metadata?.organizationName || domain,
              trustLevel: 2, // Higher trust level for well-known endpoints
              validFrom: wellKnownEntry.timestamp,
              validUntil: wellKnownEntry.timestamp + 365 * 24 * 60 * 60 * 1000, // 1 year
              services: wellKnownEntry.metadata?.services || ["auth"],
            },
          };

          this.trustRegistries.set(vaultysId.did, entry);
          return entry;
        }
      } catch (error) {
        console.error("Failed to process well-known entry:", error);
      }
    }

    // Fall back to DNS TXT record
    const dnsRecord = await this.queryDNSWoTRecord(domain);
    if (!dnsRecord) {
      return null;
    }

    try {
      const publicKey = Buffer.from(dnsRecord.publicKey, "base64");

      // Verify the signature if present
      if (dnsRecord.signature) {
        const signatureBuffer = Buffer.from(dnsRecord.signature, "base64");
        const dataToVerify = Buffer.concat([Buffer.from(dnsRecord.did), publicKey]);

        const isValid = await verify(publicKey, dataToVerify, signatureBuffer);
        if (!isValid) {
          console.error("Invalid signature for DNS record");
          return null;
        }
      }

      const entry: TrustRegistryEntry = {
        did: dnsRecord.did,
        publicKey,
        domain,
        metadata: {
          organizationName: domain,
          trustLevel: 1,
          validFrom: Date.now(),
          validUntil: Date.now() + 365 * 24 * 60 * 60 * 1000, // 1 year
        },
      };

      if (dnsRecord.certificate) {
        entry.certificateChain = [Buffer.from(dnsRecord.certificate, "base64")];
      }

      this.trustRegistries.set(dnsRecord.did, entry);
      return entry;
    } catch (error) {
      console.error("Failed to process trust anchor:", error);
      return null;
    }
  }

  /**
   * Register a trust anchor manually
   */
  registerTrustAnchor(entry: TrustRegistryEntry): void {
    this.trustRegistries.set(entry.did, entry);
  }

  /**
   * Find trust paths between two DIDs
   */
  async findTrustPaths(sourceDid: string, targetDid: string, maxDepth: number = 6): Promise<TrustPath[]> {
    const paths: TrustPath[] = [];
    const visited = new Set<string>();

    const searchPath = async (currentDid: string, path: string[], certificates: Buffer[], depth: number): Promise<void> => {
      if (depth > maxDepth || visited.has(currentDid)) {
        return;
      }

      visited.add(currentDid);
      path.push(currentDid);

      if (currentDid === targetDid) {
        paths.push({
          sourceDid,
          targetDid,
          path: [...path],
          certificates: [...certificates],
          trustScore: this.calculateTrustScore(path, certificates),
        });
        path.pop();
        visited.delete(currentDid);
        return;
      }

      // Get connections for current DID
      const connections = await this.getConnections(currentDid);

      for (const conn of connections) {
        if (conn.certificate) {
          certificates.push(conn.certificate);
          await searchPath(conn.did, path, certificates, depth + 1);
          certificates.pop();
        }
      }

      path.pop();
      visited.delete(currentDid);
    };

    await searchPath(sourceDid, [], [], 0);

    // Sort paths by trust score (highest first)
    return paths.sort((a, b) => b.trustScore - a.trustScore);
  }

  /**
   * Get connections for a DID from various sources
   */
  private async getConnections(did: string): Promise<Array<{ did: string; certificate?: Buffer }>> {
    const connections: Array<{ did: string; certificate?: Buffer }> = [];

    // Check local trust registry
    const entry = this.trustRegistries.get(did);
    if (entry && entry.certificateChain) {
      // Parse certificates to find connections
      for (const cert of entry.certificateChain) {
        try {
          const challenge = await Challenger.deserializeCertificate(cert);
          if (challenge && challenge.pk2) {
            const connectedId = VaultysId.fromId(challenge.pk2).did;
            connections.push({ did: connectedId, certificate: cert });
          }
        } catch (error) {
          console.error("Failed to parse certificate:", error);
        }
      }
    }

    return connections;
  }

  /**
   * Calculate trust score for a path
   */
  private calculateTrustScore(path: string[], certificates: Buffer[]): number {
    let score = 100;

    // Reduce score based on path length
    score -= (path.length - 2) * 10;

    // Check if path includes trusted anchors
    for (const did of path) {
      const entry = this.trustRegistries.get(did);
      if (entry) {
        score += (entry.metadata?.trustLevel || 1) * 5;
      }
    }

    // Verify all certificates are valid
    for (const cert of certificates) {
      if (!Challenger.verifyCertificate(cert)) {
        score -= 20;
      }
    }

    return Math.max(0, Math.min(100, score));
  }

  /**
   * Search for a DID across multiple web of trust networks
   */
  async searchAcrossNetworks(did: string, metadata?: Record<string, any>): Promise<TrustRegistryEntry[]> {
    const results: TrustRegistryEntry[] = [];

    // Check if metadata contains domain hints
    if (metadata?.domains) {
      for (const domain of metadata.domains) {
        const entry = await this.discoverTrustAnchors(domain);
        if (entry && entry.did === did) {
          results.push(entry);
        }
      }
    }

    // Check well-known endpoints for domains
    if (metadata?.wellKnownDomains) {
      for (const domain of metadata.wellKnownDomains) {
        const wellKnownEntry = await this.queryWellKnownEndpoint(domain);
        if (wellKnownEntry) {
          const vaultysId = VaultysId.fromId(wellKnownEntry.serverId, undefined, "base64");
          if (vaultysId.did === did) {
            const entry: TrustRegistryEntry = {
              did: vaultysId.did,
              publicKey: vaultysId.keyManager.signer.publicKey,
              domain,
              metadata: {
                organizationName: domain,
                trustLevel: 2,
                validFrom: wellKnownEntry.timestamp,
                validUntil: wellKnownEntry.timestamp + 365 * 24 * 60 * 60 * 1000,
              },
            };
            results.push(entry);
          }
        }
      }
    }

    // Check if metadata contains certificate signed by other WoT
    if (metadata?.externalCertificates) {
      for (const certData of metadata.externalCertificates) {
        try {
          const cert = Buffer.from(certData, "base64");
          const challenge = await Challenger.deserializeCertificate(cert);

          if (challenge && (await Challenger.verifyCertificate(cert))) {
            // Extract DIDs from the certificate
            const did1 = VaultysId.fromId(challenge.pk1).did;
            const did2 = VaultysId.fromId(challenge.pk2).did;

            // Check if either DID is in our trust registries
            const entry1 = this.trustRegistries.get(did1);
            const entry2 = this.trustRegistries.get(did2);

            if (entry1 || entry2) {
              // Found connection to known trust anchor
              if (did1 === did && entry1) results.push(entry1);
              if (did2 === did && entry2) results.push(entry2);
            }
          }
        } catch (error) {
          console.error("Failed to process external certificate:", error);
        }
      }
    }

    // Check all registered trust anchors
    for (const [anchorDid, entry] of this.trustRegistries) {
      if (anchorDid === did) {
        results.push(entry);
      }
    }

    return results;
  }

  /**
   * Validate a trust claim
   */
  async validateTrustClaim(claimerDid: string, targetDid: string, certificate: Buffer): Promise<boolean> {
    try {
      // Verify the certificate is valid
      if (!(await Challenger.verifyCertificate(certificate))) {
        return false;
      }

      // Deserialize the certificate
      const challenge = await Challenger.deserializeCertificate(certificate);
      if (!challenge) {
        return false;
      }

      // Check if the certificate involves the claimed DIDs
      const did1 = VaultysId.fromId(challenge.pk1).did;
      const did2 = VaultysId.fromId(challenge.pk2).did;

      if ((did1 === claimerDid && did2 === targetDid) || (did2 === claimerDid && did1 === targetDid)) {
        // Valid direct relationship
        return true;
      }

      // Check for indirect trust paths
      const paths = await this.findTrustPaths(claimerDid, targetDid);
      return paths.length > 0;
    } catch (error) {
      console.error("Failed to validate trust claim:", error);
      return false;
    }
  }

  /**
   * Export trust network for visualization
   */
  exportTrustNetwork(): {
    nodes: Array<{ id: string; label: string; metadata?: any }>;
    edges: Array<{ source: string; target: string; certificate?: string }>;
  } {
    const nodes: Array<{ id: string; label: string; metadata?: any }> = [];
    const edges: Array<{ source: string; target: string; certificate?: string }> = [];
    const processedCerts = new Set<string>();

    for (const [did, entry] of this.trustRegistries) {
      nodes.push({
        id: did,
        label: entry.metadata?.organizationName || did.slice(0, 8) + "...",
        metadata: entry.metadata,
      });

      if (entry.certificateChain) {
        for (const cert of entry.certificateChain) {
          const certHash = hash("sha256", cert).toString("hex");
          if (!processedCerts.has(certHash)) {
            processedCerts.add(certHash);

            try {
              const challenge = Challenger.deserializeCertificate(cert);
              if (challenge) {
                const did1 = VaultysId.fromId(challenge.pk1).did;
                const did2 = VaultysId.fromId(challenge.pk2).did;
                edges.push({
                  source: did1,
                  target: did2,
                  certificate: cert.toString("base64"),
                });
              }
            } catch (error) {
              console.error("Failed to process certificate for export:", error);
            }
          }
        }
      }
    }

    return { nodes, edges };
  }
}
