import { ConnectWithButton, ConnectButtonConfig } from "./ConnectWithButton";
import { WebOfTrustDiscovery, TrustRegistryEntry } from "./WebOfTrustDiscovery";
import IdManager from "../IdManager";
import VaultysId from "../VaultysId";
import { Ed25519Manager } from "../KeyManager";
import { MemoryStorage } from "../MemoryStorage";
import { Buffer } from "buffer/";

/**
 * Example implementation of VaultysID Web of Trust Sharing
 *
 * This example demonstrates:
 * 1. Setting up a "Connect with VaultysID" button
 * 2. Discovering trust anchors via DNS
 * 3. Validating cross-domain web of trust
 * 4. Finding trust paths between identities
 */

// ============================================
// 1. Basic Setup and Initialization
// ============================================

async function initializeVaultysID() {
  // Create or load an identity
  const vaultysId = await VaultysId.generatePerson();

  // Initialize storage
  const storage = MemoryStorage();

  // Create ID manager
  const idManager = new IdManager(vaultysId, storage);

  return idManager;
}

// ============================================
// 2. Implement "Connect with VaultysID" Button
// ============================================

async function setupConnectButton() {
  const idManager = await initializeVaultysID();

  // Configure the connect button
  const config: ConnectButtonConfig = {
    // Button appearance
    buttonText: "Connect with VaultysID",
    buttonStyle: {
      backgroundColor: "#007bff",
      color: "white",
      padding: "12px 24px",
      borderRadius: "8px",
      fontSize: "16px",
    },

    // Trust discovery configuration
    trustedDomains: ["example.com", "trusted-org.org", "company.com"],
    discoveryEnabled: true,
    maxTrustDepth: 6,

    // Protocol settings
    protocol: "p2p",
    service: "auth",
    liveliness: 60,

    // Metadata to share during connection
    shareMetadata: {
      domains: ["mycompany.com"],
      wellKnownDomains: ["mycompany.com", "subsidiary.com"],
      organizationName: "My Company",
      externalCertificates: [], // Certificates from other WoT networks
    },

    // Callbacks
    onConnect: async (contact, trustInfo) => {
      console.log("Successfully connected with:", contact.did);

      if (trustInfo) {
        console.log("Trust information discovered:");
        console.log("- Trust paths found:", trustInfo.trustPaths.length);
        console.log("- Trust anchors:", trustInfo.trustAnchors.length);
        console.log("- Verified domains:", trustInfo.verifiedDomains);

        // Display trust score
        if (trustInfo.trustPaths.length > 0) {
          const bestPath = trustInfo.trustPaths[0];
          console.log(`Best trust score: ${bestPath.trustScore}/100`);
          console.log(`Trust path: ${bestPath.path.join(" → ")}`);
        }
      }

      // Handle successful connection
      await handleSuccessfulConnection(contact, trustInfo);
    },

    onError: (error) => {
      console.error("Connection failed:", error);
      // Show error message to user
      showErrorMessage(error.message);
    },

    onCancel: () => {
      console.log("Connection cancelled by user");
    },
  };

  // Create and mount the button
  const connectButton = new ConnectWithButton(idManager, config);
  connectButton.mount("connect-button-container");

  return connectButton;
}

// ============================================
// 3. Web of Trust Discovery via DNS
// ============================================

async function setupWebOfTrustDiscovery() {
  // Initialize discovery service with trusted domains
  const discovery = new WebOfTrustDiscovery(["example.com", "trusted-org.org", "partner-company.com"]);

  // Discover trust anchors from DNS records
  console.log("Discovering trust anchors from DNS...");

  const trustAnchor = await discovery.discoverTrustAnchors("example.com");
  if (trustAnchor) {
    console.log(`Found trust anchor for example.com:`);
    console.log(`- DID: ${trustAnchor.did}`);
    console.log(`- Organization: ${trustAnchor.metadata?.organizationName}`);
  }

  // Manually register known trust anchors
  const manualAnchor: TrustRegistryEntry = {
    did: "did:vaultys:abc123...",
    publicKey: Buffer.from("public_key_data", "base64"),
    domain: "trusted-partner.com",
    metadata: {
      organizationName: "Trusted Partner Inc.",
      trustLevel: 5,
      validFrom: Date.now(),
      validUntil: Date.now() + 365 * 24 * 60 * 60 * 1000,
      services: ["auth", "sign", "verify"],
    },
  };

  discovery.registerTrustAnchor(manualAnchor);

  return discovery;
}

// ============================================
// 4. Cross-Domain Identity Search
// ============================================

async function searchAcrossNetworks(did: string) {
  const discovery = await setupWebOfTrustDiscovery();

  // Prepare metadata hints for search
  const searchMetadata = {
    // Domains where the identity might be registered (DNS)
    domains: ["company.com", "organization.org"],

    // Domains to check well-known endpoints
    wellKnownDomains: ["example.org", "partner.com"],

    // External certificates from other WoT networks
    externalCertificates: [
      // Base64 encoded certificates
    ],
  };

  console.log(`Searching for DID ${did} across networks...`);
  const results = await discovery.searchAcrossNetworks(did, searchMetadata);

  if (results.length > 0) {
    console.log(`Found ${results.length} trust registry entries:`);
    results.forEach((entry) => {
      console.log(`- ${entry.domain}: ${entry.metadata?.organizationName}`);
    });
  } else {
    console.log("No trust registry entries found");
  }

  return results;
}

// ============================================
// 5. Trust Path Discovery
// ============================================

async function findTrustPaths(sourceDid: string, targetDid: string) {
  const discovery = await setupWebOfTrustDiscovery();

  console.log(`Finding trust paths from ${sourceDid} to ${targetDid}...`);

  const paths = await discovery.findTrustPaths(
    sourceDid,
    targetDid,
    6, // Maximum depth
  );

  if (paths.length > 0) {
    console.log(`Found ${paths.length} trust paths:`);

    paths.forEach((path, index) => {
      console.log(`\nPath ${index + 1} (Trust Score: ${path.trustScore}/100):`);
      console.log(path.path.join(" → "));
    });

    // Return the best path (highest trust score)
    return paths[0];
  } else {
    console.log("No trust paths found");
    return null;
  }
}

// ============================================
// 6. Validate Trust Claims
// ============================================

async function validateTrustClaim(claimerDid: string, targetDid: string, certificate: Buffer) {
  const discovery = await setupWebOfTrustDiscovery();

  console.log("Validating trust claim...");

  const isValid = await discovery.validateTrustClaim(claimerDid, targetDid, certificate);

  if (isValid) {
    console.log("✓ Trust claim is valid");
  } else {
    console.log("✗ Trust claim is invalid");
  }

  return isValid;
}

// ============================================
// 7. Well-Known Endpoint Discovery
// ============================================

async function discoverViaWellKnown() {
  const discovery = await setupWebOfTrustDiscovery();

  console.log("Discovering identity via well-known endpoint...");

  // This will first check https://example.org/.well-known/vaultys.json
  // If not found, it will fall back to DNS TXT records
  const trustAnchor = await discovery.discoverTrustAnchors("example.org");

  if (trustAnchor) {
    console.log(`Found identity via well-known endpoint:`);
    console.log(`- DID: ${trustAnchor.did}`);
    console.log(`- Trust Level: ${trustAnchor.metadata?.trustLevel}`);
    console.log(`- Organization: ${trustAnchor.metadata?.organizationName}`);

    // Well-known endpoints get higher trust level (2) vs DNS (1)
    if (trustAnchor.metadata?.trustLevel === 2) {
      console.log("✓ Verified via well-known HTTPS endpoint");
    } else {
      console.log("✓ Verified via DNS TXT record");
    }
  }

  return trustAnchor;
}

// ============================================
// 8. Export Trust Network for Visualization
// ============================================

async function exportTrustNetwork() {
  const discovery = await setupWebOfTrustDiscovery();

  // Add some sample data
  await discovery.discoverTrustAnchors("example.com");
  await discovery.discoverTrustAnchors("trusted-org.org");
  await discovery.discoverTrustAnchors("example.org"); // Will check well-known first

  const network = discovery.exportTrustNetwork();

  console.log("Trust Network Export:");
  console.log(`- Nodes: ${network.nodes.length}`);
  console.log(`- Edges: ${network.edges.length}`);

  // This data can be used with graph visualization libraries
  // like D3.js, vis.js, or Cytoscape.js
  return network;
}

// ============================================
// 9. Helper Functions
// ============================================

async function handleSuccessfulConnection(contact: VaultysId, trustInfo?: any) {
  // Store the connection
  console.log("Storing new contact:", contact.did);

  // Update UI to show connected state
  updateUIConnectedState(contact);

  // If trust information is available, use it
  if (trustInfo && trustInfo.verifiedDomains.length > 0) {
    console.log("Contact is verified by domains:", trustInfo.verifiedDomains);
    // Grant additional permissions or features
  }
}

function updateUIConnectedState(contact: VaultysId) {
  // Update UI elements to show connected state
  const statusElement = document.getElementById("connection-status");
  if (statusElement) {
    statusElement.innerHTML = `
      <div class="connected">
        <span>Connected to: ${contact.fingerprint}</span>
        <span>DID: ${contact.did}</span>
      </div>
    `;
  }
}

function showErrorMessage(message: string) {
  // Display error message to user
  const errorElement = document.getElementById("error-message");
  if (errorElement) {
    errorElement.textContent = message;
    errorElement.style.display = "block";

    // Hide after 5 seconds
    setTimeout(() => {
      errorElement.style.display = "none";
    }, 5000);
  }
}

// ============================================
// 10. HTML Integration Example
// ============================================

const htmlExample = `
<!DOCTYPE html>
<html>
<head>
  <title>VaultysID Web of Trust Example</title>
  <style>
    .container {
      max-width: 800px;
      margin: 50px auto;
      padding: 20px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    }

    #connect-button-container {
      text-align: center;
      margin: 40px 0;
    }

    #connection-status {
      margin: 20px 0;
      padding: 15px;
      background: #f0f0f0;
      border-radius: 8px;
    }

    .connected {
      color: green;
    }

    #error-message {
      display: none;
      color: red;
      padding: 10px;
      background: #fee;
      border-radius: 4px;
      margin: 10px 0;
    }

    .trust-info {
      background: #e8f4ff;
      padding: 15px;
      border-radius: 8px;
      margin: 20px 0;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>VaultysID Web of Trust Connection</h1>

    <p>Click the button below to connect with your VaultysID and establish trust:</p>

    <!-- Connect button will be mounted here -->
    <div id="connect-button-container"></div>

    <!-- Connection status -->
    <div id="connection-status">
      <span>Not connected</span>
    </div>

    <!-- Error messages -->
    <div id="error-message"></div>

    <!-- Trust information display -->
    <div id="trust-info" class="trust-info" style="display: none;">
      <h3>Trust Information</h3>
      <div id="trust-details"></div>
    </div>
  </div>

  <script type="module">
    import { setupConnectButton } from './example.js';

    // Initialize the connect button when page loads
    document.addEventListener('DOMContentLoaded', async () => {
      await setupConnectButton();
    });
  </script>
</body>
</html>
`;

// ============================================
// 11. Main Function
// ============================================

async function main() {
  console.log("=== VaultysID Web of Trust Sharing Example ===\n");

  // 1. Setup connect button
  console.log("1. Setting up Connect with VaultysID button...");
  await setupConnectButton();

  // 2. Discover trust anchors
  console.log("\n2. Discovering trust anchors...");
  await setupWebOfTrustDiscovery();

  // 3. Search across networks (example DID)
  console.log("\n3. Searching across networks...");
  await searchAcrossNetworks("did:vaultys:example123");

  // 4. Find trust paths (example DIDs)
  console.log("\n4. Finding trust paths...");
  await findTrustPaths("did:vaultys:source123", "did:vaultys:target456");

  // 5. Discover via well-known endpoint
  console.log("\n5. Discovering via well-known endpoint...");
  await discoverViaWellKnown();

  // 6. Export network for visualization
  console.log("\n6. Exporting trust network...");
  const network = await exportTrustNetwork();

  console.log("\n=== Example Complete ===");

  // Return HTML example for reference
  return htmlExample;
}

// Export functions for use in other modules
export { initializeVaultysID, setupConnectButton, setupWebOfTrustDiscovery, searchAcrossNetworks, findTrustPaths, validateTrustClaim, discoverViaWellKnown, exportTrustNetwork, main };

// Run if executed directly
if (require.main === module) {
  main().catch(console.error);
}
