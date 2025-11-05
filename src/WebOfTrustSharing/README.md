# VaultysID Web of Trust Sharing Solution

## Overview

This solution enables seamless sharing and discovery of web of trust relationships across different trust domains using the VaultysID framework. It provides a "Connect with VaultysID" button for easy authentication integration and supports cross-domain trust discovery via DNS records and external certificates.

## Key Features

### 1. **Connect with VaultysID Button**
- Easy-to-integrate authentication button for web applications
- Customizable appearance and behavior
- Built-in QR code generation for mobile connectivity
- Real-time connection status updates

### 2. **Web of Trust Discovery**
- DNS-based trust anchor discovery
- Cross-domain identity search
- Trust path finding with scoring
- Certificate chain validation

3. **Trust Verification**
- Automatic trust relationship validation
- Multi-hop trust path discovery
- Trust score calculation
- Domain verification via DNS and well-known endpoints

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Web Application                          │
├─────────────────────────────────────────────────────────────┤
│                  ConnectWithButton                           │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────────┐      │
│  │  Button  │  │  Modal   │  │  Connection Handler   │      │
│  │  Render  │  │  Display │  │  (Challenge/Response) │      │
│  └──────────┘  └──────────┘  └──────────────────────┘      │
├─────────────────────────────────────────────────────────────┤
│                 WebOfTrustDiscovery                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────────┐      │
│  │   DNS    │  │  Trust   │  │    Path Finding      │      │
│  │  Query   │  │  Registry│  │    & Validation      │      │
│  └──────────┘  └──────────┘  └──────────────────────┘      │
├─────────────────────────────────────────────────────────────┤
│                  VaultysID Protocol                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────────┐      │
│  │Challenge │  │Certificate│  │    IdManager         │      │
│  │  System  │  │   Store   │  │                      │      │
│  └──────────┘  └──────────┘  └──────────────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

## Installation

```bash
npm install @vaultys/id
```

## Quick Start

### 1. Basic Setup

```typescript
import { ConnectWithButton, WebOfTrustDiscovery } from '@vaultys/id/WebOfTrustSharing';
import { IdManager } from '@vaultys/id';

// Initialize your IdManager
const idManager = await initializeIdManager();

// Create connect button
const connectButton = new ConnectWithButton(idManager, {
  buttonText: "Connect with VaultysID",
  trustedDomains: ["example.com", "trusted.org"],
  onConnect: (contact, trustInfo) => {
    console.log("Connected!", contact.did);
  }
});

// Mount to DOM
connectButton.mount("connect-button-container");
```

### 2. Identity Discovery Configuration

#### Option A: Well-Known Endpoint (Recommended)

Serve a JSON file at `https://example.org/.well-known/vaultys.json`:

```json
{
  "serverId": "AIShdgGhcMQgElUJZ+qkMSASY7D/3RHa7ONo3X58XYYmtNdDs+H+UJSheMQgQMzbrE2ADcwHYY/XOjQm9UmmaGq9hnH2bQ64vTw+ZVmhZcQg+Ubxwfp1Y+dNOi49vJWJE0CHt/8Ebw+vYpYkjelr5zc=",
  "signature": "anDSvD0r/q7Ozczt40R7Cc2HdjQ0SwFVooU/GWCXfsEtMJ6keUrvfX0wTO2M0uwoPgIr0dZs7Is6JtRPTxU5Ag==",
  "timestamp": 1761745925174,
  "metadata": {
    "organizationName": "Example Organization",
    "services": ["auth", "sign", "verify"]
  }
}
```

#### Option B: DNS TXT Record

Add a TXT record to your domain's DNS:

```
_vaultys-wot.example.com IN TXT "vaultys-wot=v=1;did=did:vaultys:abc123...;pk=<base64_public_key>;cert=<base64_cert>"
```

### 3. Trust Discovery

```typescript
const discovery = new WebOfTrustDiscovery(["example.com"]);

// Discover trust anchors (checks both well-known and DNS)
const anchor = await discovery.discoverTrustAnchors("example.com");

// Search for identity across networks
const results = await discovery.searchAcrossNetworks(did, {
  domains: ["company.com"],
  externalCertificates: [...]
});

// Find trust paths
const paths = await discovery.findTrustPaths(sourceDid, targetDid);
```

## Detailed Usage

### Connect Button Configuration

```typescript
const config: ConnectButtonConfig = {
  // Appearance
  buttonText: "Connect with VaultysID",
  buttonClass: "custom-button-class",
  buttonStyle: {
    backgroundColor: "#007bff",
    color: "white"
  },

  // Trust Discovery
  trustedDomains: ["example.com", "partner.org"],
  discoveryEnabled: true,
  maxTrustDepth: 6,

  // Protocol
  protocol: "p2p",
  service: "auth",
  liveliness: 60,

  // Metadata Sharing
  shareMetadata: {
    domains: ["mycompany.com"],
    wellKnownDomains: ["partner.com", "trusted.org"],
    organizationName: "My Company",
    externalCertificates: []
  },

  // Callbacks
  onConnect: async (contact, trustInfo) => {
    // Handle successful connection
  },
  onError: (error) => {
    // Handle errors
  },
  onCancel: () => {
    // Handle cancellation
  }
};
```

### Trust Path Discovery

The system can find trust paths between identities through intermediate connections:

```typescript
const paths = await discovery.findTrustPaths(
  "did:vaultys:alice",
  "did:vaultys:bob",
  6 // max depth
);

// Returns sorted paths by trust score
paths.forEach(path => {
  console.log(`Score: ${path.trustScore}/100`);
  console.log(`Path: ${path.path.join(" → ")}`);
});
```

### Trust Score Calculation

Trust scores are calculated based on:
- Path length (shorter = higher score)
- Presence of trusted anchors
- Certificate validity
- Domain verification

### Cross-Network Search

Search for identities across multiple web of trust networks:

```typescript
const metadata = {
  domains: ["company.com", "organization.org"],
  wellKnownDomains: ["partner.com", "subsidiary.com"],
  externalCertificates: [
    // Base64 encoded certificates from other WoT networks
  ]
};

const results = await discovery.searchAcrossNetworks(did, metadata);
```

## Security Considerations

### 1. Discovery Security
- **Well-Known Endpoints**: Serve over HTTPS with valid certificates
- **DNS Records**: Use DNSSEC when possible
- **Signature Verification**: All identities must be cryptographically verified
- **Caching**: Implement appropriate TTL (default 1 hour)

### 2. Certificate Validation
- Always verify certificate signatures
- Check certificate timestamps
- Validate certificate chains

### 3. Trust Levels
- Well-known endpoints receive higher trust scores (level 2)
- DNS records receive standard trust scores (level 1)
- Set maximum trust path depth
- Require minimum trust scores for sensitive operations

### 4. Privacy
- Share minimal metadata
- Use encryption for sensitive data
- Implement consent mechanisms

## Integration Examples

### React Component

```tsx
import React, { useEffect } from 'react';
import { ConnectWithButton } from '@vaultys/id/WebOfTrustSharing';

export function VaultysConnect({ onConnect }) {
  useEffect(() => {
    const button = new ConnectWithButton(idManager, {
      onConnect: (contact, trustInfo) => {
        onConnect(contact, trustInfo);
      }
    });
    
    button.mount("vaultys-button");
    
    return () => button.cleanup();
  }, []);

  return <div id="vaultys-button" />;
}
```

### Vue Component

```vue
<template>
  <div id="vaultys-connect-button"></div>
</template>

<script>
import { ConnectWithButton } from '@vaultys/id/WebOfTrustSharing';

export default {
  mounted() {
    this.connectButton = new ConnectWithButton(this.idManager, {
      onConnect: this.handleConnect
    });
    this.connectButton.mount("vaultys-connect-button");
  },
  methods: {
    handleConnect(contact, trustInfo) {
      this.$emit('connected', { contact, trustInfo });
    }
  },
  beforeUnmount() {
    this.connectButton?.cleanup();
  }
}
</script>
```

### HTML/Vanilla JS

```html
<!DOCTYPE html>
<html>
<head>
  <script type="module">
    import { ConnectWithButton } from './vaultysid.min.js';
    
    window.addEventListener('DOMContentLoaded', () => {
      const button = new ConnectWithButton(window.idManager, {
        buttonText: "Sign in with VaultysID",
        onConnect: (contact, trustInfo) => {
          console.log('Connected!', contact.did);
          // Update UI
        }
      });
      
      button.mount('connect-container');
    });
  </script>
</head>
<body>
  <div id="connect-container"></div>
</body>
</html>
```

## API Reference

### ConnectWithButton

#### Constructor
```typescript
new ConnectWithButton(idManager: IdManager, config?: ConnectButtonConfig)
```

#### Methods
- `mount(elementId: string): void` - Mount button to DOM element
- `updateConfig(config: Partial<ConnectButtonConfig>): void` - Update configuration
- `addTrustedDomain(domain: string): void` - Add trusted domain
- `cleanup(): void` - Clean up resources

### WebOfTrustDiscovery

#### Constructor
```typescript
new WebOfTrustDiscovery(trustedDomains?: string[])
```

#### Methods
- `discoverTrustAnchors(domain: string): Promise<TrustRegistryEntry | null>` - Discover trust anchors from well-known endpoint or DNS
- `queryWellKnownEndpoint(domain: string): Promise<WellKnownVaultysEntry | null>` - Query well-known endpoint
- `queryDNSWoTRecord(domain: string): Promise<DNSWoTRecord | null>` - Query DNS TXT record
- `searchAcrossNetworks(did: string, metadata?: any): Promise<TrustRegistryEntry[]>` - Search for DID across networks
- `findTrustPaths(source: string, target: string, maxDepth?: number): Promise<TrustPath[]>` - Find trust paths
- `validateTrustClaim(claimer: string, target: string, cert: Buffer): Promise<boolean>` - Validate trust claim
- `registerTrustAnchor(entry: TrustRegistryEntry): void` - Manually register trust anchor
- `exportTrustNetwork(): NetworkExport` - Export network for visualization

## Trust Network Visualization

Export trust network data for visualization:

```typescript
const network = discovery.exportTrustNetwork();

// Use with D3.js, vis.js, or Cytoscape.js
visualizeNetwork(network.nodes, network.edges);
```

## Testing

```bash
# Run tests
npm test

# Run example
npm run example:wot
```

## Contributing

Please see [CONTRIBUTING.md](../../CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](../../LICENSE) for details.

## Support

- Documentation: [https://docs.vaultys.com](https://docs.vaultys.com)
- GitHub Issues: [https://github.com/vaultys/vaultysid/issues](https://github.com/vaultys/vaultysid/issues)
- Discord: [https://discord.gg/vaultys](https://discord.gg/vaultys)