import { dearmorAndDecrypt, encryptAndArmor } from "@vaultys/saltpack";
import { hash, randomBytes, secureErase } from "../crypto";
import { Buffer } from "buffer/";
import nacl, { BoxKeyPair } from "tweetnacl";
import { decode, encode } from "@msgpack/msgpack";
import * as bip32fix from "@stricahq/bip32ed25519";
import { createHmac } from "crypto";
import KeyManager from "./AbstractKeyManager";

//@ts-expect-error fix for wrong way of exporting bip32ed25519
const bip32 = bip32fix.default ?? bip32fix;

const LEVEL_ROOT = 1;
const LEVEL_DERIVED = 2;

const sha512 = (data: Buffer) => hash("sha512", data);
const sha256 = (data: Buffer) => hash("sha256", data);

const serializeID_v0 = (km: DeprecatedKeyManager) => {
  const version = Buffer.from([0x84, 0xa1, 0x76, 0]);
  const proof = Buffer.from([0xa1, 0x70, 0xc5, 0x00, km.proof?.length, ...(km.proof || [])]);
  const sign = Buffer.from([0xa1, 0x78, 0xc5, 0x00, km.signer.publicKey.length, ...km.signer.publicKey]);
  const cypher = Buffer.from([0xa1, 0x65, 0xc5, 0x00, km.cypher.publicKey.length, ...km.cypher.publicKey]);
  return Buffer.concat([version, proof, sign, cypher]);
};

export const publicDerivePath = (node: InstanceType<typeof bip32.Bip32PublicKey>, path: string) => {
  let result = node;
  if (path.startsWith("m/")) path = path.slice(2);
  path.split("/").forEach((d) => {
    if (d[d.length - 1] == "'") result = result.derive(2147483648 + parseInt(d.substring(0, d.length - 1)));
    else result = result.derive(parseInt(d));
  });
  return result;
};

export const privateDerivePath = (node: InstanceType<typeof bip32.Bip32PrivateKey>, path: string) => {
  let result = node;
  if (path.startsWith("m/")) path = path.slice(2);
  path.split("/").forEach((d) => {
    if (d[d.length - 1] == "'") result = result.derive(2147483648 + parseInt(d.substring(0, d.length - 1)));
    else result = result.derive(parseInt(d));
  });
  return result;
};

export type KeyPair = {
  publicKey: Buffer;
  secretKey?: Buffer;
};

export type HISCP = {
  newId: Buffer;
  proofKey: Buffer;
  timestamp: number;
  signature: Buffer;
};

type DataExport = {
  v: 0; // version
  p: Buffer; // proof
  x: Buffer; // signing secretKey or publicKey
  e: Buffer; // encrypting secretKey or publicKey
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

export default class DeprecatedKeyManager {
  level?: number = 1;
  version: 0 | 1 = 1;
  capability: "private" | "public" = "private";
  entropy: Buffer | undefined;
  proof?: Buffer;
  proofKey!: KeyPair;
  signer!: KeyPair;
  cypher!: KeyPair;
  authType: string;
  encType: string;
  swapIndex!: number;

  constructor() {
    this.authType = "Ed25519VerificationKey2020";
    this.encType = "X25519KeyAgreementKey2019";
  }

  static async create_Id25519_fromEntropy(entropy: Buffer, swapIndex = 0) {
    const km = new DeprecatedKeyManager();
    km.entropy = entropy;
    km.level = LEVEL_ROOT;
    km.capability = "private";
    const seed = sha512(entropy);
    const derivedKey = privateDerivePath(await bip32.Bip32PrivateKey.fromEntropy(seed.slice(0, 32)), `m/1'/0'/${swapIndex}'`);
    km.proofKey = {
      publicKey: derivedKey.toBip32PublicKey().toPublicKey().toBytes(),
      secretKey: derivedKey.toBytes(),
    };
    km.swapIndex = swapIndex;
    km.proof = hash("sha256", km.proofKey.publicKey);
    const privateKey = privateDerivePath(derivedKey, "/0'");
    km.signer = {
      publicKey: privateKey.toBip32PublicKey().toPublicKey().toBytes(),
      secretKey: privateKey.toBytes(),
    };
    const swapIndexBuffer = Buffer.alloc(8);
    swapIndexBuffer.writeBigInt64LE(BigInt(swapIndex) as unknown as number, 0);
    const seed2 = sha256(Buffer.concat([seed.slice(32, 64), swapIndexBuffer]));
    const cypher = nacl.box.keyPair.fromSecretKey(seed2);
    km.cypher = {
      publicKey: Buffer.from(cypher.publicKey),
      secretKey: Buffer.from(cypher.secretKey),
    };
    return km;
  }

  static generate_Id25519() {
    return DeprecatedKeyManager.create_Id25519_fromEntropy(randomBytes(32));
  }

  get id(): Buffer {
    if (this.version == 0) return serializeID_v0(this);
    else
      return Buffer.from(
        encode({
          v: this.version,
          p: this.proof,
          x: this.signer.publicKey,
          e: this.cypher.publicKey,
        }),
      );
  }

  async getCypher() {
    // todo fetch secretKey here
    const cypher = this.cypher;
    return {
      hmac: (message: string) =>
        cypher.secretKey
          ? Buffer.from(
              createHmac("sha256", Buffer.from(cypher.secretKey).toString("hex"))
                .update("VaultysID/" + message + "/end")
                .digest(),
            )
          : undefined,
      signcrypt: async (plaintext: string, publicKeys: Buffer[]) => encryptAndArmor(plaintext, cypher as BoxKeyPair, publicKeys),
      decrypt: async (encryptedMessage: string, senderKey?: Buffer | null) => dearmorAndDecrypt(encryptedMessage, cypher as BoxKeyPair, senderKey),
      diffieHellman: async (publicKey: Buffer) => Buffer.from(nacl.scalarMult(cypher.secretKey!, publicKey)),
    };
  }

  async getSigner() {
    // todo fetch secretKey here
    const secretKey = this.signer.secretKey!;
    return new bip32.Bip32PrivateKey(secretKey).toPrivateKey();
  }

  getSecret() {
    return Buffer.from(
      encode({
        v: this.version,
        p: this.proof,
        x: this.signer.secretKey,
        e: this.cypher.secretKey,
      }),
    );
  }

  static fromSecret(secret: Buffer) {
    const data = decode(secret) as DataExport;
    const km = new DeprecatedKeyManager();
    km.version = data.v ?? 0;
    km.level = LEVEL_DERIVED;
    km.capability = "private";
    km.proof = data.p;
    km.signer = {
      secretKey: data.x,
      publicKey: new bip32.Bip32PrivateKey(data.x).toBip32PublicKey().toPublicKey().toBytes(),
    };
    const cypher = nacl.box.keyPair.fromSecretKey(data.e);
    km.cypher = {
      publicKey: Buffer.from(cypher.publicKey),
      secretKey: Buffer.from(cypher.secretKey),
    };
    return km;
  }

  static instantiate(obj: any) {
    const km = new DeprecatedKeyManager();
    km.version = obj.version ?? 0;
    km.level = obj.level;
    km.proof = obj.proof.data ? Buffer.from(obj.proof.data) : Buffer.from(obj.proof);
    km.signer = {
      publicKey: obj.signer.publicKey.data ? Buffer.from(obj.signer.publicKey.data) : Buffer.from(obj.signer.publicKey),
    };
    km.cypher = {
      publicKey: obj.cypher.publicKey.data ? Buffer.from(obj.cypher.publicKey.data) : Buffer.from(obj.cypher.publicKey),
    };
    return km;
  }

  static fromId(id: Buffer) {
    const data = decode(id) as DataExport;
    const km = new DeprecatedKeyManager();
    km.version = data.v ?? 0;
    km.level = LEVEL_DERIVED;
    km.capability = "public";
    km.proof = data.p;
    km.signer = {
      publicKey: data.x,
    };
    km.cypher = {
      publicKey: data.e,
    };
    // console.log(km)
    return km;
  }

  async sign(data: Buffer) {
    if (this.capability == "public") return null;
    const signer = await this.getSigner();
    return signer.sign(data);
  }

  verify(data: Buffer, signature: Buffer, userVerificationIgnored?: boolean): boolean {
    try {
      return bip32.Bip32PublicKey.fromBytes(this.signer.publicKey).toPublicKey().verify(signature, data);
    } catch (error) {
      //console.log(error);
      //console.log(this);
      return false;
    }
  }

  // async createRevocationCertificate(newId) {
  //   if (this.level == LEVEL_ROOT) {
  //     const seed = sha512(this.entropy);
  //     let node = derivePath(
  //       await Bip32PrivateKey.fromEntropy(seed.slice(0, 32)),
  //       "m/1'/0'/1'",
  //     );
  //     const proof = hash("sha256", node.toBip32PublicKey().toBytes());
  //     if (this.proof.toString("hex") == proof.toString("hex")) {
  //       const revocationCertificate = {
  //         xpub: node.toBytes(),
  //         id: this.id,
  //         newId,
  //       };
  //       revocationCertificate.signature = node.toPrivateKey().sign(revocationCertificate);
  //       return revocationCertificate;
  //     } else return null;
  //   } else return null;
  // }

  async createSwapingCertificate() {
    if (this.level === LEVEL_ROOT && this.entropy) {
      const newKey = await DeprecatedKeyManager.create_Id25519_fromEntropy(this.entropy, this.swapIndex + 1);

      const hiscp: HISCP = {
        newId: newKey.id,
        proofKey: this.proofKey.publicKey,
        timestamp: Date.now(),
        signature: Buffer.from([]),
      };
      const timestampBuffer = Buffer.alloc(8);
      timestampBuffer.writeBigUInt64LE(BigInt(hiscp.timestamp) as unknown as number, 0);
      const hiscpBuffer = Buffer.concat([hiscp.newId, hiscp.proofKey, timestampBuffer]);
      hiscp.signature = new bip32.Bip32PrivateKey(this.proofKey.secretKey!).toPrivateKey().sign(hiscpBuffer);
      return hiscp;
    }
    return null;
  }

  async verifySwapingCertificate(hiscp: HISCP) {
    const proof = hash("sha256", hiscp.proofKey).toString("hex");
    if (proof === this.proof?.toString("hex")) {
      const timestampBuffer = Buffer.alloc(8);
      timestampBuffer.writeBigUInt64LE(BigInt(hiscp.timestamp) as unknown as number, 0);
      const newKey = DeprecatedKeyManager.fromId(hiscp.newId);
      const hiscpBuffer = Buffer.concat([hiscp.newId, hiscp.proofKey, timestampBuffer]);
      const proofVerifier = bip32.Bip32PublicKey.fromBytes(hiscp.proofKey);
      return proofVerifier.toPublicKey().verify(hiscpBuffer, hiscp.signature);
    } else {
      return false;
    }
  }

  cleanSecureData() {
    if (this.cypher?.secretKey) {
      secureErase(this.cypher.secretKey);
      delete this.cypher.secretKey;
    }
    if (this.signer?.secretKey) {
      secureErase(this.signer.secretKey);
      delete this.signer.secretKey;
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

    // Perform the scalar multiplication to derive the shared secret
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
    const recipientKM = KeyManager.fromId(recipientId);
    //console.log(recipientKM.cypher.publicKey, this.cypher.publicKey);
    const dhies = new DHIES(this);
    return dhies.encrypt(message, recipientKM.cypher.publicKey);
  }

  /**
   * Decrypt a message encrypted with DHIES
   * @param encryptedMessage Encrypted message from dhiesEncrypt
   * @returns Decrypted message or null if decryption fails
   */
  async dhiesDecrypt(encryptedMessage: Buffer, senderId: Buffer): Promise<Buffer | null> {
    const senderKM = KeyManager.fromId(senderId);
    //console.log(senderKM.cypher.publicKey, this.cypher.publicKey);
    const dhies = new DHIES(this);
    return dhies.decrypt(encryptedMessage, senderKM.cypher.publicKey);
  }

  static async encrypt(plaintext: string, recipientIds: Buffer[]) {
    const publicKeys = recipientIds.map(KeyManager.fromId).map((km: KeyManager) => km.cypher.publicKey);
    return await encryptAndArmor(plaintext, null, publicKeys);
  }

  async signcrypt(plaintext: string, recipientIds: Buffer[]) {
    const publicKeys = recipientIds.map(KeyManager.fromId).map((km: KeyManager) => km.cypher.publicKey);
    const cypher = await this.getCypher();
    return await cypher.signcrypt(plaintext, publicKeys);
  }

  async decrypt(encryptedMessage: string, senderId: Buffer | null = null) {
    const cypher = await this.getCypher();
    const senderKey = senderId ? KeyManager.fromId(senderId).cypher.publicKey : null;
    const message = await cypher.decrypt(encryptedMessage, senderKey);
    return message.toString();
  }

  // use better hash to prevent attack
  getSecretHash(data: Buffer) {
    const toHash = Buffer.concat([data, Buffer.from("secrethash"), this.cypher.secretKey!]);
    return hash("sha256", toHash);
  }
}
