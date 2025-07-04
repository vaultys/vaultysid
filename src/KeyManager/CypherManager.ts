import { dearmorAndDecrypt, encryptAndArmor } from "@vaultys/saltpack";
import { hash, hmac, randomBytes, secureErase } from "../crypto";
import { Buffer } from "buffer/";
import nacl, { BoxKeyPair } from "tweetnacl";
import { KeyPair } from ".";
import KeyManager from "./AbstractKeyManager";
import { decode } from "@msgpack/msgpack";

const sha256 = (data: Buffer) => hash("sha256", data);

// export const publicDerivePath = (node: InstanceType<typeof bip32.Bip32PublicKey>, path: string) => {
//   let result = node;
//   if (path.startsWith("m/")) path = path.slice(2);
//   path.split("/").forEach((d) => {
//     if (d[d.length - 1] == "'") result = result.derive(2147483648 + parseInt(d.substring(0, d.length - 1)));
//     else result = result.derive(parseInt(d));
//   });
//   return result;
// };

// export const privateDerivePath = (node: InstanceType<typeof bip32.Bip32PrivateKey>, path: string) => {
//   let result = node;
//   if (path.startsWith("m/")) path = path.slice(2);
//   path.split("/").forEach((d) => {
//     if (d[d.length - 1] == "'") result = result.derive(2147483648 + parseInt(d.substring(0, d.length - 1)));
//     else result = result.derive(parseInt(d));
//   });
//   return result;
// };

export type HISCP = {
  newId: Buffer;
  proofKey: Buffer;
  timestamp: number;
  signature: Buffer;
};

/**
 * DHIES (Diffie-Hellman Integrated Encryption Scheme) for KeyManager
 * Provides authenticated encryption using Diffie-Hellman key exchange
 */
export class DHIES {
  private keyManager: KeyManager;

  constructor(keyManager: KeyManager) {
    this.keyManager = keyManager;
  }

  /**
   * Encrypts a message for a recipient using DHIES
   *
   * @param message The plaintext message to encrypt
   * @param recipientPublicKey The recipient's public key
   * @returns Encrypted message with ephemeral public key and authentication tag, or null if encryption fails
   */
  async encrypt(message: string | Buffer, recipientPublicKey: Buffer): Promise<Buffer | null> {
    if (this.keyManager.capability === "public") {
      console.error("Cannot encrypt with DHIES using a public KeyManager");
      return null;
    }

    const cypher = await this.keyManager.getCypher();

    // Convert message to Buffer if it's a string
    const messageBuffer = typeof message === "string" ? Buffer.from(message, "utf8") : message;

    try {
      const ephemeralKey = randomBytes(32); // Generate a random 32-byte key for ephemeral key

      // Derive shared secret using recipient's public key and sender secret key
      const dh = await cypher.diffieHellman(recipientPublicKey);
      const sharedSecret = Buffer.from(nacl.scalarMult(ephemeralKey, dh));

      // Key derivation: derive encryption and MAC keys from shared secret
      const kdfOutput = this.kdf(sharedSecret, this.keyManager.cypher.publicKey, recipientPublicKey);
      const encryptionKey = kdfOutput.encryptionKey;
      const macKey = kdfOutput.macKey;

      // Encrypt the message using XChaCha20-Poly1305
      const nonce = randomBytes(24); // 24 bytes nonce for XChaCha20-Poly1305
      const ciphertext = Buffer.from(nacl.secretbox(messageBuffer, nonce, encryptionKey));

      // Compute MAC (Message Authentication Code)
      const dataToAuthenticate = Buffer.concat([this.keyManager.cypher.publicKey, nonce, ciphertext]);
      const mac = this.computeMAC(macKey, dataToAuthenticate);

      // Construct the final encrypted message: nonce + ephemeralKey + ciphertext + MAC
      const encryptedMessage = Buffer.concat([nonce, ephemeralKey, ciphertext, mac]);

      // Securely erase sensitive data
      secureErase(sharedSecret);
      secureErase(dh);
      secureErase(encryptionKey);
      secureErase(macKey);

      return encryptedMessage;
    } catch (error) {
      console.error("DHIES encryption failed:", error);
      return null;
    }
  }

  /**
   * Decrypts a message encrypted with DHIES
   *
   * @param encryptedMessage The complete encrypted message from the encrypt method
   * @returns Decrypted message as a Buffer, or null if decryption fails
   */
  async decrypt(encryptedMessage: Buffer, senderPublicKey: Buffer): Promise<Buffer | null> {
    if (this.keyManager.capability === "public") {
      console.error("Cannot decrypt with DHIES using a public KeyManager");
      return null;
    }

    try {
      // Extract components from the encrypted message
      // Format: nonce (24 bytes) + ephemeralKey (32 bytes) + ciphertext + MAC (32 bytes)
      const nonce = encryptedMessage.slice(0, 24);
      const ephemeralKey = encryptedMessage.slice(24, 56);
      const mac = encryptedMessage.slice(encryptedMessage.length - 32);
      const ciphertext = encryptedMessage.slice(56, encryptedMessage.length - 32);
      const cypher = await this.keyManager.getCypher();

      // Derive shared secret using sender public key and recipient secret key
      const dh = await cypher.diffieHellman(senderPublicKey);
      const sharedSecret = Buffer.from(nacl.scalarMult(ephemeralKey, dh));

      // Key derivation: derive encryption and MAC keys
      const kdfOutput = this.kdf(sharedSecret, senderPublicKey, this.keyManager.cypher.publicKey);
      const encryptionKey = kdfOutput.encryptionKey;
      const macKey = kdfOutput.macKey;

      // Verify MAC
      const dataToAuthenticate = Buffer.concat([senderPublicKey, nonce, ciphertext]);
      const computedMac = this.computeMAC(macKey, dataToAuthenticate);

      if (!this.constantTimeEqual(mac, computedMac)) {
        //console.log(mac, computedMac);
        console.error("DHIES: MAC verification failed");
        return null;
      }

      // Decrypt the ciphertext
      const plaintext = nacl.secretbox.open(ciphertext, nonce, encryptionKey);

      if (!plaintext) {
        console.error("DHIES: Decryption failed");
        return null;
      }

      const result = Buffer.from(plaintext);

      // Securely erase sensitive data
      secureErase(sharedSecret);
      secureErase(encryptionKey);
      secureErase(macKey);

      return result;
    } catch (error) {
      console.error("DHIES decryption failed:", error);
      return null;
    }
  }

  /**
   * Key Derivation Function: Derives encryption and MAC keys from the shared secret
   */
  private kdf(sharedSecret: Buffer, ephemeralPublicKey: Buffer, staticPublicKey: Buffer) {
    // Create a context for the KDF to ensure different keys for different uses
    const context = Buffer.concat([Buffer.from("DHIES-KDF"), ephemeralPublicKey, staticPublicKey]);

    // Derive encryption key: HKDF-like construction
    const encryptionKeyMaterial = hash(
      "sha512",
      Buffer.concat([
        sharedSecret,
        context,
        Buffer.from([0x01]), // Domain separation byte
      ]),
    );

    // Derive MAC key (using a different domain separation byte)
    const macKeyMaterial = hash(
      "sha512",
      Buffer.concat([
        sharedSecret,
        context,
        Buffer.from([0x02]), // Domain separation byte
      ]),
    );

    // Use first 32 bytes of each as the actual keys (for NaCl's secretbox)
    return {
      encryptionKey: encryptionKeyMaterial.slice(0, 32),
      macKey: macKeyMaterial.slice(0, 32),
    };
  }

  /**
   * Computes MAC for authenticated encryption
   */
  private computeMAC(macKey: Buffer, data: Buffer): Buffer {
    return hash("sha256", Buffer.concat([macKey, data]));
  }

  /**
   * Constant-time comparison of two buffers to prevent timing attacks
   */
  private constantTimeEqual(a: Buffer, b: Buffer): boolean {
    if (a.length !== b.length) {
      return false;
    }

    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }

    return result === 0;
  }
}

export function getCypherPublicKeyFromId(id: Buffer) {
  const data = decode(id) as { e: Buffer };
  return data.e;
}

export default abstract class CypherManager extends KeyManager {
  version: 0 | 1 = 1;
  capability: "private" | "public" = "private";
  entropy: Buffer | undefined;
  cypher!: KeyPair;
  authType: string;
  encType: string;

  constructor() {
    super();
    this.authType = "";
    this.encType = "X25519KeyAgreementKey2019";
  }

  async getCypher() {
    // todo fetch secretKey here
    const cypher = this.cypher;
    return {
      hmac: (message: string) => (cypher.secretKey ? hmac("sha256", Buffer.from(cypher.secretKey), "VaultysID/" + message + "/end") : undefined),
      signcrypt: async (plaintext: string, publicKeys: Buffer[]) => encryptAndArmor(plaintext, cypher as BoxKeyPair, publicKeys),
      decrypt: async (encryptedMessage: string, senderKey?: Buffer | null) => dearmorAndDecrypt(encryptedMessage, cypher as BoxKeyPair, senderKey),
      diffieHellman: async (publicKey: Buffer) => Buffer.from(nacl.scalarMult(cypher.secretKey!, publicKey)),
    };
  }

  cleanSecureData() {
    if (this.cypher?.secretKey) {
      secureErase(this.cypher.secretKey);
      delete this.cypher.secretKey;
    }
    if (this.entropy) {
      secureErase(this.entropy);
      delete this.entropy;
    }
  }

  /**
   * Performs a Diffie-Hellman key exchange with another KeyManager instance
   * @param otherKeyManager The other party's KeyManager instance
   * @returns A shared secret that can be used for symmetric encryption
   */
  async performDiffieHellman(otherKeyManager: KeyManager): Promise<Buffer | null> {
    if (this.capability === "public") {
      console.error("Cannot perform DH key exchange with a public key capability");
      return null;
    }

    const cypher = await this.getCypher();
    const otherKey = otherKeyManager.cypher.publicKey;

    // Perform the X25519 scalar multiplication to derive the shared secret
    const sharedSecret = await cypher.diffieHellman(otherKey);

    // Hash the shared secret for better security (to derive a symmetric key)
    const derivedKey = sha256(sharedSecret);

    // Securely erase the shared secret from memory
    secureErase(sharedSecret);

    return derivedKey;
  }

  /**
   * Static method to perform a Diffie-Hellman key exchange between two KeyManager instances
   * @param keyManager1 First KeyManager instance
   * @param keyManager2 Second KeyManager instance
   * @returns A shared secret that both parties can derive
   */
  static async diffieHellman(keyManager1: KeyManager, keyManager2: KeyManager): Promise<Buffer | null> {
    return keyManager1.performDiffieHellman(keyManager2);
  }

  /**
   * Encrypt a message using DHIES for a recipient
   * @param message Message to encrypt
   * @param recipientId Recipient's KeyManager ID
   * @returns Encrypted message or null if encryption fails
   */
  async dhiesEncrypt(message: string | Buffer, recipientId: Buffer): Promise<Buffer | null> {
    const dhies = new DHIES(this);
    return dhies.encrypt(message, getCypherPublicKeyFromId(recipientId));
  }

  /**
   * Decrypt a message encrypted with DHIES
   * @param encryptedMessage Encrypted message from dhiesEncrypt
   * @returns Decrypted message or null if decryption fails
   */
  async dhiesDecrypt(encryptedMessage: Buffer, senderId: Buffer): Promise<Buffer | null> {
    const dhies = new DHIES(this);
    return dhies.decrypt(encryptedMessage, getCypherPublicKeyFromId(senderId));
  }

  static async encrypt(plaintext: string, recipientIds: Buffer[]) {
    const publicKeys = recipientIds.map(getCypherPublicKeyFromId);
    return await encryptAndArmor(plaintext, null, publicKeys);
  }

  async signcrypt(plaintext: string, recipientIds: Buffer[]) {
    const publicKeys = recipientIds.map(getCypherPublicKeyFromId);
    const cypher = await this.getCypher();
    return await cypher.signcrypt(plaintext, publicKeys);
  }

  async decrypt(encryptedMessage: string, senderId: Buffer | null = null) {
    const cypher = await this.getCypher();
    const senderKey = senderId ? getCypherPublicKeyFromId(senderId) : null;
    const message = await cypher.decrypt(encryptedMessage, senderKey);
    return message.toString();
  }

  // use better hash to prevent attack
  getSecretHash(data: Buffer) {
    const toHash = Buffer.concat([data, Buffer.from("secrethash"), this.cypher.secretKey!]);
    return hash("sha256", toHash);
  }
}
