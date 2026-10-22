import { dearmorAndDecrypt, encryptAndArmor } from "@vaultys/saltpack";
import { hash, hmac, secureErase } from "../crypto";
import { Buffer } from "buffer/";
import nacl, { BoxKeyPair } from "tweetnacl";
import { KeyPair } from ".";
import KeyManager from "./AbstractKeyManager";
import { dhiesV2Decrypt, dhiesV2Encrypt, dhiesV3Decrypt, dhiesV3Encrypt } from "./dhies";
import { decodeRecord, requireBytes } from "./validation";
import { deriveMlKemKeyPair, derivePrfKey, mlKemDecapsulate, MLKEM768_PK_LENGTH } from "../pqCrypto";

const sha256 = (data: Buffer) => hash("sha256", data);

export type HISCP = {
  newId: Buffer;
  proofKey: Buffer;
  timestamp: number;
  signature: Buffer;
};

/**
 * Extract the X25519 ("cypher") public key from a serialized key manager id.
 * Throws a descriptive Error when the id is malformed or the key is not 32 bytes.
 */
export function getCypherPublicKeyFromId(id: Buffer | Uint8Array) {
  const data = decodeRecord(id, "id");
  return requireBytes(data.e, "X25519 public key", 32);
}

/** The ML-KEM-768 public key (`k`) of a post-quantum id, or undefined for a classical id. */
export function getKemPublicKeyFromId(id: Buffer | Uint8Array) {
  const data = decodeRecord(id, "id");
  if (data.k === undefined) return undefined;
  return requireBytes(data.k, "ML-KEM-768 public key", MLKEM768_PK_LENGTH);
}

export default abstract class CypherManager extends KeyManager {
  version: 0 | 1 = 1;
  capability: "private" | "public" = "private";
  entropy: Buffer | undefined;
  cypher!: KeyPair;
  // post-quantum identities only (rfc/PQ-ENCRYPTION.md §3)
  kem?: KeyPair;
  prfKey?: Buffer;
  authType: string;
  encType: string;

  constructor() {
    super();
    this.authType = "";
    this.encType = "X25519KeyAgreementKey2019";
  }

  /**
   * Turn this key manager into the one of a post-quantum identity: derive the
   * ML-KEM-768 key pair and the PRF key from the full 64-byte seed.
   */
  protected derivePostQuantumKeys(seed: Buffer) {
    this.kem = deriveMlKemKeyPair(seed);
    this.prfKey = derivePrfKey(seed);
  }

  /** The key behind hmac() and getSecretHash(): the seed-derived PRF key for post-quantum identities, the X25519 secret otherwise. */
  private get hmacKey() {
    return this.prfKey ?? this.cypher.secretKey;
  }

  isPostQuantum() {
    return !!this.kem;
  }

  async getCypher() {
    // todo fetch secretKey here
    const cypher = this.cypher;
    const hmacKey = this.hmacKey;
    return {
      hmac: (message: string) => (hmacKey ? hmac("sha256", Buffer.from(hmacKey), "VaultysID/" + message + "/end") : undefined),
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
    if (this.kem?.secretKey) {
      secureErase(this.kem.secretKey);
      delete this.kem.secretKey;
    }
    if (this.prfKey) {
      secureErase(this.prfKey);
      delete this.prfKey;
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
   * Encrypt a message for a recipient: DHIES v3 (hybrid X25519 + ML-KEM-768) when
   * the recipient is a post-quantum id, DHIES v2 otherwise. Both authenticate the sender.
   * @param message Message to encrypt
   * @param recipientId Recipient's KeyManager ID
   * @returns Encrypted message or null if encryption fails
   */
  async dhiesEncrypt(message: string | Buffer, recipientId: Buffer): Promise<Buffer | null> {
    if (this.capability === "public") return null;
    try {
      const recipientPublicKey = getCypherPublicKeyFromId(recipientId);
      const recipientKemPublicKey = getKemPublicKeyFromId(recipientId);
      const cypher = await this.getCypher();
      if (recipientKemPublicKey) return await dhiesV3Encrypt(message, cypher.diffieHellman, this.cypher.publicKey, recipientPublicKey, recipientKemPublicKey);
      return await dhiesV2Encrypt(message, cypher.diffieHellman, this.cypher.publicKey, recipientPublicKey);
    } catch {
      return null;
    }
  }

  /**
   * Decrypt a DHIES message, authenticating the sender. A post-quantum identity
   * only accepts DHIES v3, a classical one only DHIES v2.
   * @param encryptedMessage Encrypted message from dhiesEncrypt
   * @param senderId Sender's KeyManager ID
   * @returns Decrypted message or null if decryption/authentication fails
   */
  async dhiesDecrypt(encryptedMessage: Buffer, senderId: Buffer): Promise<Buffer | null> {
    if (this.capability === "public") return null;
    try {
      const senderPublicKey = getCypherPublicKeyFromId(senderId);
      const cypher = await this.getCypher();
      if (this.kem) {
        const kem = this.kem;
        if (!kem.secretKey) return null;
        const decapsulate = async (cipherText: Buffer) => mlKemDecapsulate(cipherText, kem.secretKey!);
        return await dhiesV3Decrypt(encryptedMessage, cypher.diffieHellman, decapsulate, this.cypher.publicKey, kem.publicKey, senderPublicKey);
      }
      return await dhiesV2Decrypt(encryptedMessage, cypher.diffieHellman, this.cypher.publicKey, senderPublicKey);
    } catch {
      return null;
    }
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
    const toHash = Buffer.concat([data, Buffer.from("secrethash"), this.hmacKey!]);
    return hash("sha256", toHash);
  }
}
