import { Buffer } from "buffer/";
import IdManager from "../IdManager";
import VaultysId from "../VaultysId";
import Challenger from "../Challenger";
import { Channel } from "../MemoryChannel";
import { WebOfTrustDiscovery, TrustRegistryEntry } from "./WebOfTrustDiscovery";
import { encode, decode } from "@msgpack/msgpack";

/**
 * Configuration for the Connect With button
 */
export interface ConnectButtonConfig {
  // Basic configuration
  buttonText?: string;
  buttonClass?: string;
  buttonStyle?: React.CSSProperties | Record<string, string>;

  // Trust discovery configuration
  trustedDomains?: string[];
  discoveryEnabled?: boolean;
  maxTrustDepth?: number;

  // Callback functions
  onConnect?: (contact: VaultysId, trustInfo?: TrustInfo) => void;
  onError?: (error: Error) => void;
  onCancel?: () => void;

  // Protocol configuration
  protocol?: string;
  service?: string;
  liveliness?: number;

  // Metadata to share
  shareMetadata?: {
    domains?: string[];
    wellKnownDomains?: string[];
    organizationName?: string;
    externalCertificates?: string[];
  };
}

/**
 * Trust information discovered during connection
 */
export interface TrustInfo {
  trustPaths: Array<{
    path: string[];
    trustScore: number;
  }>;
  trustAnchors: TrustRegistryEntry[];
  verifiedDomains: string[];
}

/**
 * Connection result from the authentication process
 */
export interface ConnectionResult {
  contact: VaultysId;
  certificate: Buffer;
  trustInfo?: TrustInfo;
  metadata?: Record<string, any>;
}

/**
 * ConnectWithButton class for VaultysID authentication integration
 */
export class ConnectWithButton {
  private idManager: IdManager;
  private config: ConnectButtonConfig;
  private discovery: WebOfTrustDiscovery;
  private activeConnection: Channel | null = null;

  constructor(idManager: IdManager, config: ConnectButtonConfig = {}) {
    this.idManager = idManager;
    this.config = {
      buttonText: "Connect with VaultysID",
      protocol: "p2p",
      service: "auth",
      liveliness: 60,
      discoveryEnabled: true,
      maxTrustDepth: 6,
      trustedDomains: [],
      ...config,
    };

    this.discovery = new WebOfTrustDiscovery(this.config.trustedDomains || []);
  }

  /**
   * Create and mount the button to a DOM element
   */
  mount(elementId: string): void {
    const container = document.getElementById(elementId);
    if (!container) {
      throw new Error(`Element with id ${elementId} not found`);
    }

    const button = this.createButton();
    container.appendChild(button);
  }

  /**
   * Create the connect button element
   */
  private createButton(): HTMLButtonElement {
    const button = document.createElement("button");
    button.textContent = this.config.buttonText || "Connect with VaultysID";

    // Apply custom class if provided
    if (this.config.buttonClass) {
      button.className = this.config.buttonClass;
    } else {
      // Apply default styling
      this.applyDefaultStyle(button);
    }

    // Apply custom styles if provided
    if (this.config.buttonStyle) {
      Object.assign(button.style, this.config.buttonStyle);
    }

    button.addEventListener("click", () => this.handleConnect());

    return button;
  }

  /**
   * Apply default button styling
   */
  private applyDefaultStyle(button: HTMLButtonElement): void {
    Object.assign(button.style, {
      backgroundColor: "#4A90E2",
      color: "white",
      border: "none",
      borderRadius: "6px",
      padding: "12px 24px",
      fontSize: "16px",
      fontWeight: "600",
      cursor: "pointer",
      transition: "all 0.3s ease",
      boxShadow: "0 2px 4px rgba(0,0,0,0.1)",
      display: "inline-flex",
      alignItems: "center",
      gap: "8px",
    });

    // Add hover effect
    button.addEventListener("mouseenter", () => {
      button.style.backgroundColor = "#357ABD";
      button.style.boxShadow = "0 4px 8px rgba(0,0,0,0.15)";
    });

    button.addEventListener("mouseleave", () => {
      button.style.backgroundColor = "#4A90E2";
      button.style.boxShadow = "0 2px 4px rgba(0,0,0,0.1)";
    });
  }

  /**
   * Handle the connect button click
   */
  private async handleConnect(): Promise<void> {
    try {
      // Show connection modal
      const modal = this.createConnectionModal();
      document.body.appendChild(modal);

      // Initialize connection
      const result = await this.initiateConnection();

      // Process the connection result
      if (result) {
        await this.processConnectionResult(result);

        // Call success callback
        if (this.config.onConnect) {
          this.config.onConnect(result.contact, result.trustInfo);
        }
      }

      // Clean up modal
      document.body.removeChild(modal);
    } catch (error) {
      console.error("Connection failed:", error);
      if (this.config.onError) {
        this.config.onError(error as Error);
      }
    }
  }

  /**
   * Create a modal for the connection process
   */
  private createConnectionModal(): HTMLDivElement {
    const modal = document.createElement("div");
    modal.id = "vaultys-connect-modal";

    Object.assign(modal.style, {
      position: "fixed",
      top: "0",
      left: "0",
      width: "100%",
      height: "100%",
      backgroundColor: "rgba(0, 0, 0, 0.5)",
      display: "flex",
      justifyContent: "center",
      alignItems: "center",
      zIndex: "10000",
    });

    const content = document.createElement("div");
    Object.assign(content.style, {
      backgroundColor: "white",
      borderRadius: "12px",
      padding: "24px",
      maxWidth: "400px",
      width: "90%",
      boxShadow: "0 10px 40px rgba(0,0,0,0.2)",
    });

    content.innerHTML = `
      <h2 style="margin: 0 0 16px 0; font-size: 24px; color: #333;">
        Connecting with VaultysID
      </h2>
      <p style="color: #666; margin: 0 0 20px 0;">
        Please follow the authentication process in your VaultysID app.
      </p>
      <div id="vaultys-qr-container" style="display: flex; justify-content: center; margin: 20px 0;">
        <!-- QR code or connection string will be displayed here -->
      </div>
      <div style="display: flex; justify-content: flex-end; gap: 12px; margin-top: 20px;">
        <button id="vaultys-cancel-btn" style="
          padding: 8px 16px;
          border: 1px solid #ddd;
          background: white;
          border-radius: 6px;
          cursor: pointer;
          font-size: 14px;
        ">Cancel</button>
      </div>
    `;

    content.querySelector("#vaultys-cancel-btn")?.addEventListener("click", () => {
      this.cancelConnection();
      document.body.removeChild(modal);
    });

    modal.appendChild(content);
    return modal;
  }

  /**
   * Initiate the connection process
   */
  private async initiateConnection(): Promise<ConnectionResult | null> {
    try {
      // Create a channel for communication
      const channel = await this.createChannel();
      this.activeConnection = channel;

      // Display connection string or QR code
      await this.displayConnectionInfo(channel);

      // Prepare metadata to share
      const metadata = this.prepareMetadata();

      // Perform the authentication challenge
      const contact = await this.performAuthentication(channel, metadata);

      if (!contact) {
        return null;
      }

      // Discover trust information if enabled
      let trustInfo: TrustInfo | undefined;
      if (this.config.discoveryEnabled) {
        trustInfo = await this.discoverTrustInfo(contact, metadata);
      }

      return {
        contact,
        certificate: contact.certificate!,
        trustInfo,
        metadata,
      };
    } catch (error) {
      console.error("Failed to initiate connection:", error);
      throw error;
    }
  }

  /**
   * Create a communication channel
   */
  private async createChannel(): Promise<Channel> {
    // This would typically create a WebSocket, WebRTC, or other channel
    // For demonstration, using a placeholder
    throw new Error("Channel creation must be implemented based on your transport layer");
  }

  /**
   * Display connection information (QR code or connection string)
   */
  private async displayConnectionInfo(channel: Channel): Promise<void> {
    const container = document.getElementById("vaultys-qr-container");
    if (!container) return;

    const connectionString = channel.getConnectionString();

    // Generate QR code (requires a QR code library)
    const qrCanvas = await this.generateQRCode(connectionString);
    if (qrCanvas) {
      container.appendChild(qrCanvas);
    }

    // Also show connection string
    const textElement = document.createElement("div");
    textElement.style.cssText = "margin-top: 12px; font-family: monospace; font-size: 12px; word-break: break-all; color: #666;";
    textElement.textContent = connectionString;
    container.appendChild(textElement);
  }

  /**
   * Generate QR code for connection string
   */
  private async generateQRCode(data: string): Promise<HTMLCanvasElement | null> {
    // This would use a QR code library like qrcode.js
    // Placeholder implementation
    const canvas = document.createElement("canvas");
    canvas.width = 200;
    canvas.height = 200;
    canvas.style.border = "1px solid #ddd";

    const ctx = canvas.getContext("2d");
    if (ctx) {
      ctx.fillStyle = "#f0f0f0";
      ctx.fillRect(0, 0, 200, 200);
      ctx.fillStyle = "#666";
      ctx.font = "14px Arial";
      ctx.textAlign = "center";
      ctx.fillText("QR Code", 100, 100);
    }

    return canvas;
  }

  /**
   * Prepare metadata to share during connection
   */
  private prepareMetadata(): Record<string, any> {
    const metadata: Record<string, any> = {
      timestamp: Date.now(),
      protocol: this.config.protocol,
      service: this.config.service,
    };

    // Add shared metadata if configured
    if (this.config.shareMetadata) {
      Object.assign(metadata, this.config.shareMetadata);

      // If domains are specified but not wellKnownDomains, use domains for both
      if (this.config.shareMetadata.domains && !this.config.shareMetadata.wellKnownDomains) {
        metadata.wellKnownDomains = this.config.shareMetadata.domains;
      }
    }

    // Add local identity information
    metadata.did = this.idManager.vaultysId.did;
    metadata.name = this.idManager.displayName;

    // Add certificates from existing connections for trust discovery
    const contacts = this.idManager.contacts;
    if (contacts.length > 0) {
      metadata.knownContacts = contacts.slice(0, 5).map((c) => ({
        did: c.did,
        fingerprint: c.fingerprint,
      }));
    }

    return metadata;
  }

  /**
   * Perform the authentication challenge
   */
  private async performAuthentication(channel: Channel, metadata: Record<string, any>): Promise<VaultysId | null> {
    try {
      // Create challenger with metadata
      const challenger = new Challenger(this.config.protocol!, this.config.service!, this.idManager.vaultysId, metadata);

      // Set protocol version
      challenger.version = this.idManager.protocol_version;

      // Perform the challenge-response protocol
      await channel.start();

      // Send initial challenge
      const challenge = challenger.create();
      await channel.send(encode(challenge));

      // Wait for response
      const response = await channel.receive();
      const responseData = decode(response) as any;

      // Process response
      const processedChallenge = await challenger.process(responseData);

      // Complete the challenge
      const completed = await challenger.complete(processedChallenge);
      await channel.send(encode(completed));

      // Verify and create contact
      if (await Challenger.verifyCertificate(completed)) {
        const contact = VaultysId.fromId(responseData.pk2, Buffer.from(completed));

        // Save to contacts
        this.idManager.saveContact(contact);

        return contact;
      }

      return null;
    } catch (error) {
      console.error("Authentication failed:", error);
      throw error;
    } finally {
      await channel.close();
    }
  }

  /**
   * Discover trust information for the connected identity
   */
  private async discoverTrustInfo(contact: VaultysId, metadata: Record<string, any>): Promise<TrustInfo> {
    const trustInfo: TrustInfo = {
      trustPaths: [],
      trustAnchors: [],
      verifiedDomains: [],
    };

    // Search for the contact across networks
    const entries = await this.discovery.searchAcrossNetworks(contact.did, metadata);
    trustInfo.trustAnchors = entries;

    // Find trust paths from our identity to the contact
    const paths = await this.discovery.findTrustPaths(this.idManager.vaultysId.did, contact.did, this.config.maxTrustDepth);

    trustInfo.trustPaths = paths.map((p) => ({
      path: p.path,
      trustScore: p.trustScore,
    }));

    // Check for verified domains (both DNS and well-known)
    const domainsToCheck = [...(metadata.domains || []), ...(metadata.wellKnownDomains || [])];

    const uniqueDomains = [...new Set(domainsToCheck)];

    for (const domain of uniqueDomains) {
      const anchor = await this.discovery.discoverTrustAnchors(domain);
      if (anchor && anchor.did === contact.did) {
        trustInfo.verifiedDomains.push(domain);
      }
    }

    return trustInfo;
  }

  /**
   * Process the connection result
   */
  private async processConnectionResult(result: ConnectionResult): Promise<void> {
    // Store trust information
    if (result.trustInfo) {
      this.idManager.setContactMetadata(result.contact.did, "trustInfo", result.trustInfo);
    }

    // Store additional metadata
    if (result.metadata) {
      this.idManager.setContactMetadata(result.contact.did, "connectionMetadata", result.metadata);
    }

    // Save the updated contact information
    this.idManager.store.save();
  }

  /**
   * Cancel the active connection
   */
  private cancelConnection(): void {
    if (this.activeConnection) {
      this.activeConnection.close();
      this.activeConnection = null;
    }

    if (this.config.onCancel) {
      this.config.onCancel();
    }
  }

  /**
   * Update configuration
   */
  updateConfig(config: Partial<ConnectButtonConfig>): void {
    this.config = { ...this.config, ...config };

    if (config.trustedDomains) {
      this.discovery = new WebOfTrustDiscovery(config.trustedDomains);
    }
  }

  /**
   * Add a trusted domain for discovery
   */
  addTrustedDomain(domain: string): void {
    this.config.trustedDomains?.push(domain);
    this.discovery.addTrustedDomain(domain);
  }
}
