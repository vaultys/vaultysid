import { IdManager, VaultysId, LocalStorage } from "@vaultys/id";

// Initialize VaultysID from storage
export async function initVaultysId() {
  try {
    const storage = LocalStorage("vaultysStorage").substore("id");

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
    const storage = LocalStorage("vaultysStorage");
    let manager;

    if (!storage.listSubstores().find((key) => key === "id")) {
      let vaultysId;
      try {
        // Create a WebAuthn credential if supported
        vaultysId = await VaultysId.createWebauthn(true);
        if (!vaultysId) {
          throw new Error("WebAuthn credential creation failed");
        }
      } catch (err) {
        console.warn("WebAuthn not available, falling back to software key:", err);
        vaultysId = await VaultysId.generatePerson();
      }
      manager = new IdManager(vaultysId, storage.substore("id"));
    } else {
      manager = await IdManager.fromStore(storage.substore("id"));
    }

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
    const storage = LocalStorage("vaultysStorage").substore("id");
    const vaultysId = await VaultysId.generatePerson();
    const manager = new IdManager(vaultysId, storage);
    storage.save();
    return manager;
  } catch (err) {
    console.error("Error creating VaultysID:", err);
    throw new Error("Failed to create VaultysID: " + err.message);
  }
}

// Setup PeerJS Channel
export async function setupPeerJsChannel(idManager) {
  try {
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
  localStorage.removeItem("vaultysStorage");
}
