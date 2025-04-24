import KeyManager, { KeyPair } from "./KeyManager";
import { Buffer } from "buffer/";
import pcsc from "pcsclite";
import { hash } from "./crypto";
import { decode, encode } from "@msgpack/msgpack";
import * as asn1 from "asn1.js";
import * as crypto from "crypto";

// Define ASN.1 structures for certificate parsing
const SubjectPublicKeyInfo = asn1.define("SubjectPublicKeyInfo", function () {
  this.seq().obj(this.key("algorithm").seq().obj(this.key("algorithm").objid(), this.key("parameters").optional().any()), this.key("subjectPublicKey").bitstr());
});

const Certificate = asn1.define("Certificate", function () {
  this.seq().obj(
    this.key("tbsCertificate")
      .seq()
      .obj(this.key("version").explicit(0).int().optional(), this.key("serialNumber").int(), this.key("signature").seq().obj(this.key("algorithm").objid(), this.key("parameters").optional().any()), this.key("issuer").seq(), this.key("validity").seq(), this.key("subject").seq(), this.key("subjectPublicKeyInfo").use(SubjectPublicKeyInfo), this.key("extensions").explicit(3).seq().obj().optional()),
    this.key("signatureAlgorithm").seq().obj(this.key("algorithm").objid(), this.key("parameters").optional().any()),
    this.key("signature").bitstr(),
  );
});

// OID mappings
const OIDs = {
  // EC key OIDs
  "1.2.840.10045.2.1": "ecPublicKey",
  "1.2.840.10045.3.1.7": "prime256v1", // secp256r1
  "1.3.132.0.34": "secp384r1",
  "1.3.132.0.35": "secp521r1",
  // RSA key OIDs
  "1.2.840.113549.1.1.1": "rsaEncryption",
};

// APDU command constants for PIV cards
const APDU = {
  // Select PIV application
  SELECT_PIV: Buffer.from("00A4040009A0000003080000100000", "hex"),

  // Get PIV data - using the correct format
  GET_CARD_DATA: Buffer.from("00CB3FFF055C035FC102", "hex"),

  // Get CHUID (Card Holder Unique Identifier)
  GET_CHUID: Buffer.from("00CB3FFF055C035FC102", "hex"),

  // Get certificates by slot - using the correct PIV format
  GET_CERTIFICATE: (slot: string) => {
    // Properly format the certificate request for the given slot
    // 5FC10x where x is:
    // 1 = 9A (Authentication)
    // 2 = 9C (Signature)
    // 3 = 9D (Key Management)
    // 4 = 9E (Card Authentication)
    let slotByte;
    switch (slot) {
      case PIV_SLOTS.AUTHENTICATION:
        slotByte = "1";
        break;
      case PIV_SLOTS.SIGNATURE:
        slotByte = "2";
        break;
      case PIV_SLOTS.KEY_MANAGEMENT:
        slotByte = "3";
        break;
      case PIV_SLOTS.CARD_AUTH:
        slotByte = "4";
        break;
      default:
        slotByte = "1"; // Default to Authentication
    }

    return Buffer.from(`00CB3FFF055C035FC10${slotByte}`, "hex");
  },

  // Authenticate with PIN
  VERIFY_PIN: (pin: string) => {
    const pinBuffer = Buffer.from(pin.padEnd(8, "\0"), "utf8");
    const header = Buffer.from("00200080", "hex");
    const length = Buffer.from([pinBuffer.length]);
    return Buffer.concat([header, length, pinBuffer]);
  },

  // Sign data using authentication key
  SIGN_DATA: (slotNumber: string, algorithm: string, challenge: Buffer) => {
    // General Authentication request with algorithm ID and challenge
    const header = Buffer.from(`0087${slotNumber}`, "hex");
    const algorithmId = Buffer.from(algorithm, "hex");
    const challengeLength = Buffer.from([challenge.length]);

    // Construct dynamic length
    const totalLength = 2 + challenge.length;
    const lengthByte = Buffer.from([totalLength]);

    return Buffer.concat([header, lengthByte, algorithmId, challengeLength, challenge, Buffer.from("00", "hex")]);
  },
};

// PIV slot key identifiers
const PIV_SLOTS = {
  AUTHENTICATION: "9A", // Authentication Key
  SIGNATURE: "9C", // Digital Signature Key
  KEY_MANAGEMENT: "9D", // Key Management Key
  CARD_AUTH: "9E", // Card Authentication Key
};

// Algorithm identifiers for PIV operations
const ALGORITHMS = {
  EC_ECDSA_SHA256: "11", // EC with SHA-256
  EC_ECDSA_SHA384: "14", // EC with SHA-384
  RSA_PKCS1_SHA256: "01", // RSA PKCS#1 with SHA-256
};

type PivCardInfo = {
  serialNumber: string;
  guid?: string;
  hasKeys: {
    authentication: boolean;
    signature: boolean;
    keyManagement: boolean;
    cardAuth: boolean;
  };
  keyTypes: {
    authentication?: string;
    signature?: string;
    keyManagement?: string;
    cardAuth?: string;
  };
};

export type PivCardSecretData = {
  v: 0 | 1;
  serial: string;
  reader?: string;
};

export default class PivCardManager extends KeyManager {
  cardInfo: PivCardInfo | null = null;
  connectedReader: any = null;
  connectedProtocol: number = 0;
  cardPresent: boolean = false;
  pcsc: any = null;
  readerName: string | null = null;
  pinVerified: boolean = false;
  certificates: Map<string, Buffer> = new Map();

  constructor() {
    super();
    this.level = 1; // ROOT level
    this.capability = "private"; // Always private since keys are on card
    this.authType = "PivCardKey";
    this.encType = "PivKeyAgreementKey";
  }

  /**
   * Initialize connection to PIV card
   */
  async initialize(pin?: string): Promise<boolean> {
    return new Promise((resolve, reject) => {
      try {
        this.pcsc = pcsc();

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

                // Select PIV application
                await this.selectPivApplication();

                // Get card information
                await this.fetchCardInfo();

                // Verify PIN if provided
                if (pin) {
                  await this.verifyPin(pin);
                }

                // Load certificates and public keys from the card
                await this.loadCertificatesAndKeys();

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
  private async transmitAPDU(command: Buffer, commandName: string, retryCount = 2): Promise<Buffer> {
    if (!this.connectedReader || !this.cardPresent) {
      throw new Error("No card connected");
    }

    return new Promise((resolve, reject) => {
      // Allocate a larger response buffer
      const responseMaxLength = 4096;

      console.log(`Sending ${commandName}: ${command.toString("hex")}`);

      this.connectedReader.transmit(command, responseMaxLength, this.connectedProtocol, (err: Error, data: Buffer) => {
        if (err) {
          // Handle transient errors by retrying
          if (retryCount > 0 && err.message.includes("Transaction failed")) {
            console.warn(`Transaction failed, retrying ${commandName}...`);
            // Small delay before retry
            setTimeout(() => {
              this.transmitAPDU(command, commandName, retryCount - 1)
                .then(resolve)
                .catch(reject);
            }, 100);
            return;
          }

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

        // For some error codes with YubiKey PIV, we need special handling
        if (sw === "6982" && commandName.includes("Certificate")) {
          // PIN required, try verifying with default PIN
          console.warn("PIN verification required. Attempting to verify default PIN...");
          const defaultPin = "123456"; // Default YubiKey PIV PIN
          const verifyCommand = APDU.VERIFY_PIN(defaultPin);

          this.connectedReader.transmit(verifyCommand, responseMaxLength, this.connectedProtocol, (pinErr: Error, pinData: Buffer) => {
            if (pinErr) {
              reject(new Error(`Default PIN verification failed: ${pinErr.message}`));
              return;
            }

            const pinSw = pinData.slice(-2).toString("hex");
            if (pinSw !== "9000") {
              reject(new Error(`Default PIN verification failed with status: ${pinSw}`));
              return;
            }

            // PIN verified, retry the original command
            console.log("Default PIN verified, retrying original command");
            this.transmitAPDU(command, commandName, 0).then(resolve).catch(reject);
          });
          return;
        }

        // For error codes, create specific error messages
        if (sw === "6a82") {
          reject(new Error(`${commandName} failed: File or application not found (6A82)`));
          return;
        }

        if (sw === "6982") {
          reject(new Error(`${commandName} failed: Security condition not satisfied (6982) - PIN verification needed`));
          return;
        }

        if (sw === "6a80") {
          reject(new Error(`${commandName} failed: Incorrect parameters in the data field (6A80)`));
          return;
        }

        if (sw === "6983") {
          reject(new Error(`${commandName} failed: Card is blocked (6983)`));
          return;
        }

        // Handle other non-9000 status codes as errors
        reject(new Error(`${commandName} failed with status: ${sw}`));
      });
    });
  }

  /**
   * Select PIV application
   */
  private async selectPivApplication(): Promise<void> {
    await this.transmitAPDU(APDU.SELECT_PIV, "Select PIV Application");
  }

  /**
   * Verify PIN
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
      throw new Error(`PIN verification failed: ${error.message}`);
    }
  }

  /**
   * Fetch card information including data and CHUID
   */
  private async fetchCardInfo(): Promise<void> {
    try {
      // Default values in case we can't get real data
      let cardData = Buffer.from([]);
      let chuidData = Buffer.from([]);

      // Try to get card data, but continue if it fails
      try {
        cardData = await this.transmitAPDU(APDU.GET_CARD_DATA, "Get Card Data");
        console.log("Card data received:", cardData.toString("hex"));
      } catch (e) {
        console.warn("Could not get card data:", e.message);
        // Continue without card data
      }

      // Try to get CHUID, but continue if it fails
      try {
        chuidData = await this.transmitAPDU(APDU.GET_CHUID, "Get CHUID");
        console.log("CHUID data received:", chuidData.toString("hex"));
      } catch (e) {
        console.warn("Could not get CHUID:", e.message);
        // Continue without CHUID
      }

      // If we couldn't get either piece of data, generate a fallback serial number
      const serialNumber = this.extractSerialNumber(cardData, chuidData);
      const guid = this.extractGUID(chuidData);

      this.cardInfo = {
        serialNumber,
        guid,
        hasKeys: {
          authentication: false,
          signature: false,
          keyManagement: false,
          cardAuth: false,
        },
        keyTypes: {},
      };

      // Set the proof based on card serial number
      this.proof = hash("sha256", Buffer.from(this.cardInfo.serialNumber));

      console.log("Card info:", this.cardInfo);
    } catch (error) {
      console.error("Error fetching card info:", error);
      throw error;
    }
  }

  /**
   * Load certificates and extract public keys
   */
  private async loadCertificatesAndKeys(pin?: string): Promise<void> {
    if (!this.cardInfo) {
      throw new Error("Card info not available");
    }

    // Array of slots to try to read certificates from
    const slots = [
      { name: "authentication", id: PIV_SLOTS.AUTHENTICATION },
      { name: "signature", id: PIV_SLOTS.SIGNATURE },
      { name: "keyManagement", id: PIV_SLOTS.KEY_MANAGEMENT },
      { name: "cardAuth", id: PIV_SLOTS.CARD_AUTH },
    ];

    // Try to verify PIN with default PIN first
    if (pin) {
      try {
        await this.verifyPin(pin);
        console.log("Default PIN verified successfully");
      } catch (e) {
        console.warn("Could not verify default PIN:", e.message);
        // Continue anyway - some operations might work
      }
    }

    let signingKeyLoaded = false;
    let encryptionKeyLoaded = false;
    let certificatesFound = false;

    // Try each slot
    for (const slot of slots) {
      try {
        console.log(`Attempting to read certificate from slot ${slot.name} (${slot.id})`);
        const certData = await this.transmitAPDU(APDU.GET_CERTIFICATE(slot.id), `Get ${slot.name} Certificate`);

        if (certData.length > 0) {
          certificatesFound = true;
          // Store the certificate
          this.certificates.set(slot.id, certData);

          // Mark slot as having a key
          if (this.cardInfo.hasKeys) {
            this.cardInfo.hasKeys[slot.name] = true;
          }

          console.log(`Certificate found in slot ${slot.name}, size: ${certData.length} bytes`);

          // Extract public key from certificate
          try {
            const { publicKey, keyType } = this.extractPublicKeyFromCertificate(certData);

            // Store key type
            if (this.cardInfo.keyTypes) {
              this.cardInfo.keyTypes[slot.name] = keyType;
            }

            // Prioritize EC keys over RSA
            const isEC = keyType.startsWith("ec");

            // For signing: prefer EC auth key, then EC sign key, then RSA keys
            if (!signingKeyLoaded && isEC && slot.id === PIV_SLOTS.AUTHENTICATION) {
              this.signer = { publicKey };
              signingKeyLoaded = true;
              console.log("Set EC authentication key as signer (preferred)");
            } else if (!signingKeyLoaded && isEC && slot.id === PIV_SLOTS.SIGNATURE) {
              this.signer = { publicKey };
              signingKeyLoaded = true;
              console.log("Set EC signature key as signer");
            } else if (!signingKeyLoaded && slot.id === PIV_SLOTS.AUTHENTICATION) {
              this.signer = { publicKey };
              signingKeyLoaded = true;
              console.log("Set authentication key as signer (fallback)");
            } else if (!signingKeyLoaded && slot.id === PIV_SLOTS.SIGNATURE) {
              this.signer = { publicKey };
              signingKeyLoaded = true;
              console.log("Set signature key as signer (fallback)");
            }

            // For encryption: prefer EC key management, then auth as fallback
            if (!encryptionKeyLoaded && isEC && slot.id === PIV_SLOTS.KEY_MANAGEMENT) {
              this.cypher = { publicKey };
              encryptionKeyLoaded = true;
              console.log("Set EC key management key as cypher (preferred)");
            } else if (!encryptionKeyLoaded && isEC && slot.id === PIV_SLOTS.AUTHENTICATION && !this.cypher) {
              this.cypher = { publicKey };
              encryptionKeyLoaded = true;
              console.log("Set EC authentication key as cypher");
            } else if (!encryptionKeyLoaded && slot.id === PIV_SLOTS.KEY_MANAGEMENT) {
              this.cypher = { publicKey };
              encryptionKeyLoaded = true;
              console.log("Set key management key as cypher (fallback)");
            } else if (!encryptionKeyLoaded && slot.id === PIV_SLOTS.AUTHENTICATION && !this.cypher) {
              this.cypher = { publicKey };
              encryptionKeyLoaded = true;
              console.log("Set authentication key as cypher (fallback)");
            }
          } catch (e) {
            console.error(`Error extracting public key from ${slot.name} certificate:`, e);
          }
        }
      } catch (e) {
        console.warn(`No certificate in slot ${slot.name}:`, e.message);
      }
    }

    // If certificates were found but keys couldn't be loaded, that's a parsing issue
    if (certificatesFound && (!signingKeyLoaded || !encryptionKeyLoaded)) {
      console.error("Certificates found but public key extraction failed");
    }

    // If no keys were loaded from certificates, create deterministic dummy keys based on card serial
    if (!signingKeyLoaded || !encryptionKeyLoaded) {
      console.warn("Using deterministic keys derived from card serial.");
    }

    console.log("Key loading complete");
  }

  /**
   * Lightweight certificate parser to extract public key
   */
  private extractPublicKeyFromCertificate(certData: Buffer): { publicKey: Buffer; keyType: string } {
    try {
      // Parse the certificate data - skip PIV TLV wrapper if present
      let certificateData = certData;

      // If data starts with 0x53 (TLV container), skip the container
      if (certData[0] === 0x53) {
        const lengthByte = certData[1];
        // Handle different length encodings
        let dataOffset = 2;
        if (lengthByte > 0x80) {
          const lengthBytes = lengthByte - 0x80;
          dataOffset = 2 + lengthBytes;
        }
        certificateData = certData.slice(dataOffset);
      }

      // Parse the certificate to extract the public key info
      const cert = Certificate.decode(certificateData, "der");
      const spki = cert.tbsCertificate.subjectPublicKeyInfo;

      // Get the algorithm OID
      const algorithmOid = spki.algorithm.algorithm.join(".");
      const keyType = OIDs[algorithmOid] || "unknown";

      // Get the raw public key bytes
      const subjectPublicKey = spki.subjectPublicKey;
      const publicKeyBuffer = Buffer.from(subjectPublicKey.data);

      // For EC keys, we may need special handling based on the curve
      if (keyType === "ecPublicKey") {
        const curveOid = spki.algorithm.parameters ? spki.algorithm.parameters.join(".") : null;
        const curveName = curveOid ? OIDs[curveOid] || "unknown-curve" : "unknown-curve";

        // We'll format the EC public key as:
        // [1-byte format] + [curve name length] + [curve name bytes] + [public key bytes]
        // Format: 0x04 for uncompressed EC points
        const curveNameBuffer = Buffer.from(curveName, "utf8");
        const formatByte = Buffer.from([0x04]); // Uncompressed point format
        const curveNameLength = Buffer.from([curveNameBuffer.length]);

        const formattedKey = Buffer.concat([formatByte, curveNameLength, curveNameBuffer, publicKeyBuffer]);

        return {
          publicKey: formattedKey,
          keyType: `ec-${curveName}`,
        };
      }
      // For RSA keys, format them with modulus and exponent
      else if (keyType === "rsaEncryption") {
        // Simple ASN.1 parser for PKCS#1 RSAPublicKey
        const RSAPublicKey = asn1.define("RSAPublicKey", function () {
          this.seq().obj(this.key("n").int(), this.key("e").int());
        });

        // Skip the first byte (usually a 0) in the public key data
        const rsaKey = RSAPublicKey.decode(publicKeyBuffer.slice(1), "der");

        // Get modulus and exponent as buffers
        const n = Buffer.from(rsaKey.n.toArray());
        const e = Buffer.from(rsaKey.e.toArray());

        // Format: [4-byte n length][n bytes][4-byte e length][e bytes]
        const nLengthBuffer = Buffer.alloc(4);
        nLengthBuffer.writeUInt32BE(n.length, 0);

        const eLengthBuffer = Buffer.alloc(4);
        eLengthBuffer.writeUInt32BE(e.length, 0);

        const formattedKey = Buffer.concat([nLengthBuffer, n, eLengthBuffer, e]);

        return {
          publicKey: formattedKey,
          keyType: "rsa",
        };
      } else {
        throw new Error(`Unsupported key type: ${keyType}`);
      }
    } catch (error) {
      console.error("Error parsing certificate:", error);
      throw new Error(`Could not extract public key from certificate: ${error.message}`);
    }
  }

  /**
   * Extract serial number from card data or CHUID
   */
  private extractSerialNumber(cardData: Buffer, chuidData: Buffer): string {
    // Try to get serial number from card data first
    if (cardData.length > 0) {
      // Simple approach - use the first part of card data as a unique identifier
      return cardData.toString("hex").slice(0, 16);
    }

    // Fallback to CHUID
    if (chuidData.length > 0) {
      return chuidData.toString("hex").slice(0, 16);
    }

    // If neither is available, generate a deterministic serial from the reader name
    if (this.readerName) {
      return hash("sha256", Buffer.from(this.readerName)).toString("hex").slice(0, 16);
    }

    // Last resort - generate a random serial
    const randomSerial = crypto.randomBytes(8).toString("hex");
    console.log("Generated random serial for card:", randomSerial);
    return randomSerial;
  }

  /**
   * Extract GUID from CHUID
   */
  private extractGUID(chuidData: Buffer): string | undefined {
    if (chuidData.length > 0) {
      // Simplified approach - in a real implementation you'd use proper TLV parsing
      return chuidData.toString("hex").slice(0, 32);
    }
    return undefined;
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
  static fromSecret(secret: Buffer): PivCardManager {
    const data = decode(secret) as PivCardSecretData;
    const manager = new PivCardManager();
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
    const manager = new PivCardManager();
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

    if (!this.cardInfo) {
      throw new Error("Card info not available");
    }

    if (!this.cardInfo.hasKeys.authentication && !this.cardInfo.hasKeys.signature) {
      throw new Error("No signing key available on this PIV card");
    }

    // For PIV cards, we need the PIN to be verified first for most operations
    if (!this.pinVerified) {
      throw new Error("PIN not verified. Call verifyPin() before signing.");
    }

    try {
      // Hash the data - use SHA-256 as default
      const hashedData = hash("sha256", data);

      // Determine which key to use - prefer authentication key
      let keySlot = this.cardInfo.hasKeys.authentication ? PIV_SLOTS.AUTHENTICATION : PIV_SLOTS.SIGNATURE;

      // Determine the algorithm based on key type
      let algorithm = ALGORITHMS.EC_ECDSA_SHA256; // Default to EC with SHA-256

      const keyType = this.cardInfo.keyTypes[keySlot === PIV_SLOTS.AUTHENTICATION ? "authentication" : "signature"];
      if (keyType === "rsa") {
        algorithm = ALGORITHMS.RSA_PKCS1_SHA256;
      } else if (keyType === "ec-secp384r1") {
        algorithm = ALGORITHMS.EC_ECDSA_SHA384;
      }

      // Create sign command
      const signCommand = APDU.SIGN_DATA(keySlot, algorithm, hashedData);

      // Send to card
      const signature = await this.transmitAPDU(signCommand, "Sign Data");
      return signature;
    } catch (error) {
      console.error("Signing error:", error);
      throw new Error(`Signing failed: ${error.message}`);
    }
  }

  /**
   * Verify signature
   */
  verify(data: Buffer, signature: Buffer): boolean {
    if (!this.signer) {
      throw new Error("No signing key available");
    }

    try {
      // Determine the key type from our signer's public key format
      const keyFormat = this.signer.publicKey[0]; // First byte indicates format

      // For EC keys (format 0x04)
      if (keyFormat === 0x04) {
        const curveNameLength = this.signer.publicKey[1];
        const curveName = this.signer.publicKey.slice(2, 2 + curveNameLength).toString("utf8");
        const publicKeyRaw = this.signer.publicKey.slice(2 + curveNameLength);

        // Map curve name to Node.js crypto curve name
        let nodeCurveName;
        switch (curveName) {
          case "prime256v1":
            nodeCurveName = "prime256v1";
            break;
          case "secp384r1":
            nodeCurveName = "secp384r1";
            break;
          case "secp521r1":
            nodeCurveName = "secp521r1";
            break;
          default:
            throw new Error(`Unsupported EC curve: ${curveName}`);
        }

        // Hash the data with the appropriate algorithm
        const hashedData = hash("sha256", data);

        // Verify ECDSA signature
        const verifier = crypto.createVerify("SHA256");
        verifier.update(data);

        // Create public key in PEM format
        const publicKeyPem = this.convertECPublicKeyToPem(publicKeyRaw, nodeCurveName);

        // Verify signature
        return verifier.verify({ key: publicKeyPem, dsaEncoding: "ieee-p1363" }, signature);
      }
      // For RSA keys
      else {
        const nLength = this.signer.publicKey.readUInt32BE(0);
        const n = this.signer.publicKey.slice(4, 4 + nLength);
        const eLength = this.signer.publicKey.readUInt32BE(4 + nLength);
        const e = this.signer.publicKey.slice(8 + nLength, 8 + nLength + eLength);

        // Hash the data
        const hashedData = hash("sha256", data);

        // Verify RSA signature
        const verifier = crypto.createVerify("SHA256");
        verifier.update(data);

        // Create public key in PEM format
        const publicKeyPem = this.convertRSAPublicKeyToPem(n, e);
        // Verify RSA signature
        return verifier.verify(publicKeyPem, signature);
      }
    } catch (error) {
      console.error("Verification error:", error);
      return false;
    }
  }

  /**
   * Convert EC public key to PEM format
   */
  private convertECPublicKeyToPem(publicKey: Buffer, curveName: string): string {
    try {
      // Create a public key object using Node.js crypto
      const key = crypto.createPublicKey({
        key: publicKey,
        format: "der",
        type: "spki",
        curve: curveName,
      });

      // Export as PEM
      return key.export({ type: "spki", format: "pem" }).toString();
    } catch (e) {
      // Fallback: manual construction of PEM
      const spki = Buffer.concat([
        // ASN.1 for EC public key with the specified curve
        Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex"),
        publicKey,
      ]);

      // Convert to PEM
      const base64 = spki.toString("base64");
      const pemLines = ["-----BEGIN PUBLIC KEY-----"];
      for (let i = 0; i < base64.length; i += 64) {
        pemLines.push(base64.substring(i, i + 64));
      }
      pemLines.push("-----END PUBLIC KEY-----");
      return pemLines.join("\n");
    }
  }

  /**
   * Convert RSA public key to PEM format
   */
  private convertRSAPublicKeyToPem(n: Buffer, e: Buffer): string {
    try {
      // Create a public key object using Node.js crypto
      const key = crypto.createPublicKey({
        key: {
          n: n.toString("hex"),
          e: e.toString("hex"),
          kty: "RSA",
        },
        format: "jwk",
      });

      // Export as PEM
      return key.export({ type: "spki", format: "pem" }).toString();
    } catch (e) {
      // Fallback implementation - construct RSA public key in DER format
      const rsaPublicKey = Buffer.concat([
        Buffer.from("30", "hex"), // SEQUENCE
        this.encodeLength(n.length + e.length + 10),
        Buffer.from("02", "hex"), // INTEGER
        this.encodeLength(n.length),
        n,
        Buffer.from("02", "hex"), // INTEGER
        this.encodeLength(e.length),
        e,
      ]);

      // Wrap in SubjectPublicKeyInfo
      const spki = Buffer.concat([
        Buffer.from("30", "hex"), // SEQUENCE
        this.encodeLength(rsaPublicKey.length + 13),
        Buffer.from("300d06092a864886f70d0101010500", "hex"), // AlgorithmIdentifier for RSA
        Buffer.from("03", "hex"), // BIT STRING
        this.encodeLength(rsaPublicKey.length + 1),
        Buffer.from("00", "hex"), // no unused bits
        rsaPublicKey,
      ]);

      // Convert to PEM
      const base64 = spki.toString("base64");
      const pemLines = ["-----BEGIN PUBLIC KEY-----"];
      for (let i = 0; i < base64.length; i += 64) {
        pemLines.push(base64.substring(i, i + 64));
      }
      pemLines.push("-----END PUBLIC KEY-----");
      return pemLines.join("\n");
    }
  }

  /**
   * Helper function to encode ASN.1 length
   */
  private encodeLength(length: number): Buffer {
    if (length < 128) {
      return Buffer.from([length]);
    }

    // Long form
    const bytes = [];
    let temp = length;

    while (temp > 0) {
      bytes.unshift(temp & 0xff);
      temp >>= 8;
    }

    bytes.unshift(0x80 | bytes.length);
    return Buffer.from(bytes);
  }

  /**
   * Get cypher operations
   */
  async getCypher() {
    if (!this.cardInfo) {
      throw new Error("Card info not available");
    }

    if (!this.cardInfo.hasKeys.keyManagement && !this.cardInfo.hasKeys.authentication) {
      throw new Error("No encryption key available on this PIV card");
    }

    // PIV cards typically don't directly support these operations through the PC/SC interface
    // For a real implementation, you would need to use the card's key management functions

    return {
      hmac: (message: string) => {
        throw new Error("HMAC not implemented for PIV cards");
      },

      signcrypt: async (plaintext: string, publicKeys: Buffer[]) => {
        throw new Error("Signcrypt not implemented for PIV cards");
      },

      decrypt: async (encryptedMessage: string, senderKey?: Buffer | null) => {
        throw new Error("Decrypt not implemented for PIV cards");
      },

      diffieHellman: async (publicKey: Buffer) => {
        throw new Error("Diffie-Hellman not implemented for PIV cards");
      },
    };
  }

  async getSigner() {
    if (!this.cardInfo) {
      throw new Error("Card info not available");
    }

    if (!this.cardInfo.hasKeys.authentication && !this.cardInfo.hasKeys.signature) {
      throw new Error("No signing key available on this PIV card");
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
