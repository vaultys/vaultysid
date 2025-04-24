import KeyManager, { KeyPair } from "./KeyManager";
import { Buffer } from "buffer/";
import pscs from "pcsclite";
import { hash } from "./crypto";
import { decode, encode } from "@msgpack/msgpack";

// APDU command constants for OpenPGP cards
const APDU = {
  // Select OpenPGP application
  SELECT_OPENPGP: Buffer.from("00A4040006D27600012401", "hex"),
  // Get application data
  GET_APPLICATION_DATA: Buffer.from("00CA006E00", "hex"),
  // Get cardholder name
  GET_CARDHOLDER_NAME: Buffer.from("00CA005B00", "hex"),
  // Get URL for public key
  GET_URL: Buffer.from("00CA5F5000", "hex"),
  // Get key related data
  GET_SIGNATURE_KEY: Buffer.from("00470046000000", "hex"),
  GET_ENCRYPTION_KEY: Buffer.from("00470047000000", "hex"),
  GET_AUTHENTICATION_KEY: Buffer.from("00470049000000", "hex"),
  // Verify PIN
  VERIFY_PIN: (pin: string) => {
    const pinBuffer = Buffer.from(pin, "utf8");
    const header = Buffer.from("00200082", "hex");
    const length = Buffer.from([pinBuffer.length]);
    return Buffer.concat([header, length, pinBuffer]);
  },
};

type PgpCardInfo = {
  serialNumber: string;
  cardholderName?: string;
  appVersion?: string;
  hasKeys: boolean;
  keysAccessible: boolean;
};

export type PgpCardSecretData = {
  v: 0 | 1;
  serial: string;
  reader?: string;
};

export default class PgpCardManager extends KeyManager {
  cardInfo: PgpCardInfo | null = null;
  connectedReader: any = null;
  connectedProtocol: number = 0;
  cardPresent: boolean = false;
  pcsc: any = null;
  readerName: string | null = null;
  pinVerified: boolean = false;

  constructor() {
    super();
    this.level = 1; // ROOT level
    this.capability = "private"; // Always private since keys are on card
    this.authType = "PgpCard25519Key";
    this.encType = "PgpCardEncryptionKey";
  }

  /**
   * Initialize connection to PGP card
   */
  async initialize(pin?: string): Promise<boolean> {
    return new Promise((resolve, reject) => {
      try {
        this.pcsc = pscs();

        this.pcsc.on("error", (err: Error) => {
          console.error("PCSC error:", err.message);
          reject(err);
        });

        this.pcsc.on("reader", (reader: any) => {
          console.log(`Reader detected: ${reader.name}`);
          this.readerName = reader.name;

          reader.on("error", (err: Error) => {
            console.error(`Reader error: ${err.message}`);
          });

          reader.on("status", async (status: any) => {
            const changes = reader.state ^ status.state;

            // Card was inserted
            if (changes & reader.SCARD_STATE_PRESENT && status.state & reader.SCARD_STATE_PRESENT) {
              this.cardPresent = true;

              try {
                // Connect to the card
                await this.connectCard(reader);

                // Select OpenPGP application on the card
                await this.selectOpenPgpApplication();

                // Get card information
                await this.fetchCardInfo();

                // Verify PIN if provided
                if (pin) {
                  await this.verifyPin(pin);
                }

                // Try to load keys
                await this.loadKeysOrFail();

                resolve(true);
              } catch (error) {
                console.error("Card initialization error:", error);
                reject(error);
              }
            }

            // Card was removed
            if (changes & reader.SCARD_STATE_EMPTY && status.state & reader.SCARD_STATE_EMPTY) {
              this.cardPresent = false;
              this.connectedReader = null;
              this.connectedProtocol = 0;
              console.log("Card removed");
            }
          });
        });
      } catch (error) {
        console.error("Failed to initialize card manager:", error);
        reject(error);
      }
    });
  }

  /**
   * Connect to the card
   */
  private async connectCard(reader: any): Promise<void> {
    return new Promise((resolve, reject) => {
      reader.connect({ share_mode: reader.SCARD_SHARE_EXCLUSIVE }, (err: Error, protocol: number) => {
        if (err) {
          reject(new Error(`Connection error: ${err.message}`));
          return;
        }

        this.connectedReader = reader;
        this.connectedProtocol = protocol;
        console.log("Connected to card with protocol:", protocol);
        resolve();
      });
    });
  }

  /**
   * Send APDU command to the card with basic response handling
   */
  private async transmitAPDU(command: Buffer, commandName: string): Promise<Buffer> {
    if (!this.connectedReader || !this.cardPresent) {
      throw new Error("No card connected");
    }

    return new Promise((resolve, reject) => {
      // Allocate a larger response buffer
      const responseMaxLength = 4096;

      console.log(`Sending ${commandName}: ${command.toString("hex")}`);

      this.connectedReader.transmit(command, responseMaxLength, this.connectedProtocol, (err: Error, data: Buffer) => {
        if (err) {
          reject(new Error(`Error in ${commandName}: ${err.message}`));
          return;
        }

        // Check response status (last 2 bytes)
        const sw = data.slice(-2).toString("hex");
        console.log(`${commandName} response status: ${sw}, length: ${data.length}`);

        // Handle status 61XX - more data available
        if (sw.startsWith("61")) {
          // The second byte indicates how many bytes are available
          const remainingLength = parseInt(sw.substring(2), 16);
          console.log(`More data available: ${remainingLength} bytes`);

          // Send GET RESPONSE command to get the remaining data
          const getResponseCommand = Buffer.from(`00C00000${sw.substring(2)}`, "hex");
          console.log(`Sending GET RESPONSE command: ${getResponseCommand.toString("hex")}`);

          this.connectedReader.transmit(getResponseCommand, responseMaxLength, this.connectedProtocol, (err: Error, moreData: Buffer) => {
            if (err) {
              reject(new Error(`Error in GET RESPONSE: ${err.message}`));
              return;
            }

            const moreSw = moreData.slice(-2).toString("hex");
            console.log(`GET RESPONSE status: ${moreSw}, length: ${moreData.length}`);

            if (!moreSw.startsWith("90")) {
              reject(new Error(`GET RESPONSE failed with status: ${moreSw}`));
              return;
            }

            // Combine the data (excluding status words) and return
            const firstPartData = data.length > 2 ? data.slice(0, -2) : Buffer.from([]);
            const secondPartData = moreData.slice(0, -2);
            const combinedData = Buffer.concat([firstPartData, secondPartData]);

            console.log(`${commandName} succeeded with ${combinedData.length} bytes of data`);
            resolve(combinedData);
          });
          return;
        }

        // 9000 = success
        if (sw === "9000") {
          console.log(`${commandName} succeeded with ${data.length - 2} bytes of data`);
          resolve(data.slice(0, -2)); // Remove status bytes
          return;
        }

        // For error codes, create specific error messages
        if (sw === "6b00") {
          reject(new Error(`${commandName} failed: Function not supported (6B00)`));
          return;
        }

        if (sw === "6a88") {
          reject(new Error(`${commandName} failed: Referenced data not found (6A88)`));
          return;
        }

        if (sw === "6a80") {
          reject(new Error(`${commandName} failed: Incorrect parameters (6A80)`));
          return;
        }

        if (sw === "6982") {
          reject(new Error(`${commandName} failed: Security status not satisfied (6982) - PIN required`));
          return;
        }

        // Handle other non-9000 status codes as errors
        reject(new Error(`${commandName} failed with status: ${sw}`));
      });
    });
  }

  /**
   * Select the OpenPGP application on the card
   */
  private async selectOpenPgpApplication(): Promise<void> {
    await this.transmitAPDU(APDU.SELECT_OPENPGP, "Select OpenPGP Application");
  }

  /**
   * Verify PIN to access protected operations
   */
  async verifyPin(pin: string): Promise<boolean> {
    try {
      const verifyCommand = APDU.VERIFY_PIN(pin);
      await this.transmitAPDU(verifyCommand, "Verify PIN");
      this.pinVerified = true;
      console.log("PIN verification successful");
      return true;
    } catch (error) {
      console.error("PIN verification failed:", error);
      this.pinVerified = false;
      return false;
    }
  }

  /**
   * Fetch card information
   */
  private async fetchCardInfo(): Promise<void> {
    try {
      // Get application data
      const applicationData = await this.transmitAPDU(APDU.GET_APPLICATION_DATA, "Get Application Data");
      console.log("Application data received:", applicationData.toString("hex"));

      // Try to get cardholder name
      let nameData = Buffer.from([]);
      try {
        nameData = await this.transmitAPDU(APDU.GET_CARDHOLDER_NAME, "Get Cardholder Name");
        console.log("Name data received:", nameData.toString("hex"));
      } catch (e) {
        console.warn("Could not get cardholder name:", e);
      }

      // Parse the application data
      const appInfo = this.parseApplicationData(applicationData);

      this.cardInfo = {
        serialNumber: this.extractSerialNumber(applicationData),
        cardholderName: nameData.length > 0 ? this.parseCardholderName(nameData) : "Unknown",
        appVersion: this.extractAppVersion(applicationData),
        hasKeys: appInfo.hasKeys,
        keysAccessible: false, // Will be set later when we try to access the keys
      };

      console.log("Card info:", this.cardInfo);

      // Set the proof based on card serial number
      this.proof = hash("sha256", Buffer.from(this.cardInfo.serialNumber));
    } catch (error) {
      console.error("Error fetching card info:", error);
      throw error;
    }
  }

  /**
   * Load keys from the card or fail with a clear message
   */
  private async loadKeysOrFail(): Promise<void> {
    if (!this.cardInfo) {
      throw new Error("Card info not available");
    }

    // If the card doesn't have keys, fail immediately
    if (!this.cardInfo.hasKeys) {
      throw new Error("No keys are present on this OpenPGP card. Please generate or import keys to the card first.");
    }

    // Try to get the public keys from the card
    try {
      const signingKeyData = await this.transmitAPDU(APDU.GET_SIGNATURE_KEY, "Get Signature Key");
      const encryptionKeyData = await this.transmitAPDU(APDU.GET_ENCRYPTION_KEY, "Get Encryption Key");

      // Extract the actual public keys from the response data
      this.signer = {
        publicKey: this.parsePublicKey(signingKeyData, "signing"),
      };

      this.cypher = {
        publicKey: this.parsePublicKey(encryptionKeyData, "encryption"),
      };

      // Keys are accessible
      if (this.cardInfo) {
        this.cardInfo.keysAccessible = true;
      }

      console.log("Successfully loaded public keys from card");
    } catch (error) {
      // Mark keys as not accessible
      if (this.cardInfo) {
        this.cardInfo.keysAccessible = false;
      }

      // Provide clear error message
      throw new Error(`Could not access keys on the OpenPGP card: ${error.message}\n` + `This may be because:\n` + `1. The keys need to be generated or imported on the card first\n` + `2. PIN verification is required before accessing the keys\n` + `3. The card or reader doesn't support retrieving public keys via PC/SC interface\n\n` + `You may need to use external tools like GnuPG or YubiKey Manager to set up the keys.`);
    }
  }

  /**
   * Parse the application data to extract key information
   */
  private parseApplicationData(data: Buffer): { hasKeys: boolean } {
    let hasKeys = false;

    // Check for key fingerprints in the data
    // In OpenPGP card application data, fingerprints are typically stored in the Security Support Template
    // with zeros (all 0x00) indicating no key is present

    // Simple heuristic: if we find a fingerprint that's not all zeros, keys are likely present
    let allZeros = true;
    for (let i = 100; i < data.length; i++) {
      // Start at offset 100 to skip headers
      if (data[i] !== 0x00) {
        allZeros = false;
        break;
      }
    }

    // If not all zeros, we likely have at least one key
    hasKeys = !allZeros;

    console.log(`Card has keys: ${hasKeys}`);
    return { hasKeys };
  }

  /**
   * Extract serial number from application data
   */
  private extractSerialNumber(data: Buffer): string {
    // For some YubiKeys, the serial number is included directly in the AID
    // If we couldn't extract it properly, use the raw application data
    return data.toString("hex").substring(0, 16);
  }

  /**
   * Extract application version
   */
  private extractAppVersion(data: Buffer): string {
    // Look for version info in application data
    // This is a simplified approach
    for (let i = 0; i < data.length - 3; i++) {
      // Common pattern for OpenPGP version info
      if (data[i] === 0x5f && data[i + 1] === 0x52) {
        const len = data[i + 2];
        if (i + 3 + len <= data.length) {
          const versionData = data.slice(i + 3, i + 3 + len);
          return `${versionData[0]}.${versionData[1]}.${versionData[2]}`;
        }
      }
    }
    return "Unknown";
  }

  /**
   * Parse cardholder name from data
   */
  private parseCardholderName(data: Buffer): string {
    try {
      return data.toString("utf8").trim();
    } catch (e) {
      return "Unknown";
    }
  }

  /**
   * Parse public key from card data
   */
  private parsePublicKey(data: Buffer, keyType: string): Buffer {
    console.log(`Parsing ${keyType} key:`, data.toString("hex"));

    // Since the format depends on the specific key type and card implementation,
    // a proper implementation would parse the DER structure

    // For now, we'll just verify the data is non-empty and return it
    if (data.length === 0) {
      throw new Error(`Empty ${keyType} key data received from card`);
    }

    // This is a simplification - real implementation would parse the key structure
    return data;
  }

  /**
   * Get the card ID
   */
  get id(): Buffer {
    if (!this.signer || !this.cypher) {
      throw new Error("Keys not available - card not properly initialized");
    }

    return Buffer.from(
      encode({
        v: this.version,
        p: this.proof,
        x: this.signer.publicKey,
        e: this.cypher.publicKey,
      }),
    );
  }

  /**
   * Get the secret data (only card reference, not actual private keys)
   */
  getSecret(): Buffer {
    if (!this.cardInfo) {
      throw new Error("Card info not available");
    }

    return Buffer.from(
      encode({
        v: this.version,
        serial: this.cardInfo.serialNumber,
        reader: this.readerName,
      }),
    );
  }

  /**
   * Create a KeyManager from secret data
   */
  static fromSecret(secret: Buffer): PgpCardManager {
    const data = decode(secret) as PgpCardSecretData;
    const manager = new PgpCardManager();
    manager.version = data.v ?? 0;

    // Note: This only creates the manager, but doesn't connect to card
    // Call initialize() after this to connect to the card
    return manager;
  }

  /**
   * Create from ID
   */
  static fromId(id: Buffer): KeyManager {
    const data = decode(id) as any;
    const manager = new PgpCardManager();
    manager.version = data.v ?? 0;
    manager.capability = "public";
    manager.proof = data.p;
    manager.signer = {
      publicKey: data.x,
    };
    manager.cypher = {
      publicKey: data.e,
    };
    return manager;
  }

  /**
   * Sign data using the card
   */
  async sign(data: Buffer): Promise<Buffer | null> {
    if (!this.cardPresent || !this.connectedReader) {
      throw new Error("Card not connected");
    }

    if (!this.cardInfo?.hasKeys) {
      throw new Error("No keys present on this OpenPGP card");
    }

    if (!this.cardInfo?.keysAccessible) {
      throw new Error("Keys are present but not accessible. PIN verification may be required.");
    }

    // For OpenPGP cards, we typically need the PIN to be verified first
    if (!this.pinVerified) {
      throw new Error("PIN not verified. Call verifyPin() before signing.");
    }

    try {
      // Hash the data (cards typically require pre-hashed data)
      const hashedData = hash("sha256", data);

      // Prepare the APDU command for signing
      // Note: The specific command depends on your card's implementation
      const command = Buffer.from(`002A9E9A${hashedData.length.toString(16).padStart(2, "0")}${hashedData.toString("hex")}`, "hex");

      // Try to sign with card
      const signature = await this.transmitAPDU(command, "Compute Signature");
      return signature;
    } catch (error) {
      console.error("Signing error:", error);
      throw new Error(`Signing failed: ${error.message}`);
    }
  }

  /**
   * Verify signature (using public key operations)
   */
  verify(data: Buffer, signature: Buffer): boolean {
    throw new Error("Verification not implemented for this specific card type");
  }

  /**
   * Perform Diffie-Hellman operations for DHIES
   */
  async getCypher() {
    if (!this.cardInfo?.hasKeys) {
      throw new Error("No keys present on this OpenPGP card");
    }

    if (!this.cardInfo?.keysAccessible) {
      throw new Error("Keys are present but not accessible. PIN verification may be required.");
    }

    return {
      hmac: (message: string) => {
        throw new Error("HMAC not implemented for this card type");
      },

      signcrypt: async (plaintext: string, publicKeys: Buffer[]) => {
        throw new Error("Signcrypt not implemented for this card type");
      },

      decrypt: async (encryptedMessage: string, senderKey?: Buffer | null) => {
        throw new Error("Decrypt not implemented for this card type");
      },

      diffieHellman: async (publicKey: Buffer) => {
        throw new Error("Diffie-Hellman not implemented for this card type");
      },
    };
  }

  async getSigner() {
    if (!this.cardInfo?.hasKeys) {
      throw new Error("No keys present on this OpenPGP card");
    }

    if (!this.cardInfo?.keysAccessible) {
      throw new Error("Keys are present but not accessible. PIN verification may be required.");
    }

    return {
      sign: async (data: Buffer) => {
        return this.sign(data);
      },
    };
  }

  /**
   * Close the connection and clean up resources
   */
  async close(): Promise<void> {
    if (this.connectedReader) {
      return new Promise((resolve) => {
        this.connectedReader.disconnect(this.connectedReader.SCARD_LEAVE_CARD, (err: Error) => {
          if (err) {
            console.error("Error disconnecting from card:", err);
          }

          this.connectedReader = null;
          this.cardPresent = false;

          if (this.pcsc) {
            this.pcsc.close();
          }

          resolve();
        });
      });
    }

    if (this.pcsc) {
      this.pcsc.close();
    }

    return Promise.resolve();
  }

  /**
   * Clean any sensitive data from memory
   */
  cleanSecureData() {
    // No need to clean private keys as they never leave the card
  }
}
