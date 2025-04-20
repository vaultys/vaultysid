import { IdManager, VaultysId, LocalStorage } from "@vaultys/id";

// Initialize VaultysID
export async function initVaultysId() {
  try {
    const storage = LocalStorage("bitcoinWalletStorage").substore("id");

    if (storage.get("secret") || storage.get("entropy")) {
      // ID already exists, load it
      const manager = await IdManager.fromStore(storage);
      return { idManager: manager, isCreating: false };
    } else {
      // Need to create a new ID
      return { idManager: null, isCreating: true };
    }
  } catch (err) {
    console.error("Error initializing VaultysID:", err);
    throw new Error("Failed to initialize VaultysID: " + err.message);
  }
}

// Create WebAuthn ID
export async function createWebAuthnId() {
  try {
    const storage = LocalStorage("bitcoinWalletStorage");
    let manager;

    let vaultysId;
    try {
      // Create a WebAuthn credential if supported
      vaultysId = await VaultysId.createWebauthn(true);
      if (!vaultysId) {
        throw new Error("WebAuthn credential creation failed");
      }
    } catch (err) {
      console.warn("WebAuthn not available, falling back to software key:", err);
      vaultysId = await VaultysId.generateMachine();
    }
    manager = new IdManager(vaultysId, storage.substore("id"));

    storage.save();
    return manager;
  } catch (err) {
    console.error("Error creating VaultysID:", err);
    throw new Error("Failed to create VaultysID: " + err.message);
  }
}

// Create Software ID
export async function createSoftwareId() {
  try {
    const storage = LocalStorage("bitcoinWalletStorage").substore("id");
    const vaultysId = await VaultysId.generateMachine();
    const manager = new IdManager(vaultysId, storage);
    return manager;
  } catch (err) {
    console.error("Error creating VaultysID:", err);
    throw new Error("Failed to create VaultysID: " + err.message);
  }
}

export async function requestPRFComputation(idManager, derivationPath, callbacks = {}) {
  try {
    const { onChannelSetup, onStatusUpdate } = callbacks;

    const { channel, channelUrl } = await setupPeerJsChannel(idManager);

    // Notify for QR code update
    if (onChannelSetup) {
      onChannelSetup(channelUrl);
    }

    if (onStatusUpdate) {
      onStatusUpdate("Channel ready. Scan the QR code with your mobile device to continue.");
    }

    // Setup connection handler
    channel.onConnected(() => {
      if (onStatusUpdate) {
        onStatusUpdate("Connected to remote device. Processing PRF computation...");
      }
    });

    // Request PRF computation
    const result = await idManager.requestPRF(channel, derivationPath);

    if (onStatusUpdate) {
      onStatusUpdate("PRF computation completed successfully!");
    }

    // Close the channel
    channel.close();

    return { result, channelUrl };
  } catch (error) {
    console.error("PRF computation error:", error);
    throw error;
  }
}

// Make sure setupPeerJsChannel also supports callbacks
export async function setupPeerJsChannel(idManager, callbacks = {}) {
  try {
    const { onStatusUpdate } = callbacks;

    if (onStatusUpdate) {
      onStatusUpdate("Setting up secure channel...");
    }

    const { PeerjsChannel } = await import("@vaultys/channel-peerjs");
    const channel = new PeerjsChannel();

    // Start the channel
    channel.start();

    // Get connection string
    const connectionString = channel.getConnectionString();
    const idString = idManager?.vaultysId?.id.toString("base64") || "";

    // Create URL with channel info
    const channelUrl = `https://wallet.vaultys.net#${connectionString}&protocol=p2p&service=file_encryption&id=${idString}`;

    return { channel, channelUrl };
  } catch (err) {
    console.error("Failed to setup PeerJS channel:", err);
    throw new Error("Failed to setup secure channel: " + err.message);
  }
}

// Reset Identity
export function resetIdentity() {
  localStorage.removeItem("bitcoinWalletStorage");
}

// Get derivation path for Bitcoin account (m/44'/0'/0'/0)
export function getDerivationPath(index = 0) {
  return `m/44'/0'/0'/0/${index}`;
}

// Compute HMAC-based PRF locally
export async function computeLocalPRF(idManager, derivationPath) {
  // This would be a local alternative when remote isn't available
  // For simplicity, we're using a basic HMAC approach
  try {
    // Get identity secret as key
    return idManager.vaultysId.hmac("prf|" + derivationPath + "|prf");
  } catch (error) {
    console.error("Local PRF computation error:", error);
    throw error;
  }
}
