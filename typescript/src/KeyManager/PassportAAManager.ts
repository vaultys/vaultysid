import { encode } from "@msgpack/msgpack";
import { Buffer } from "buffer/";
import nacl from "tweetnacl";
import { hash, randomBytes } from "../crypto";
import { parsePassportKey, readDG14Hash, readDG15 } from "../passport/keys";
import type { PassportAAReader } from "../passport/reader";
import CypherManager from "./CypherManager";
import { decodeRecord, requireBytes } from "./validation";

export const TYPE_PASSPORT_AA = 5;
const DOMAIN = Buffer.from("VAULTYS_PASSPORT_AA_V1", "ascii");
const CHALLENGE_BYTES = 8;
const CHALLENGE_COUNT = 4;
const DIGEST_BYTES = 32;

export interface PassportAAOptions {
  /** EF.DG15, or its unwrapped DER SubjectPublicKeyInfo. */
  dg15: Uint8Array;
  /** EF.DG14 or its unwrapped SecurityInfos. Required for ECDSA. */
  dg14?: Uint8Array;
  reader: PassportAAReader;
  /** Stable, locally managed 32-byte X25519 secret. */
  encryptionSecretKey: Uint8Array;
}

export default class PassportAAManager extends CypherManager {
  readonly ecdsaHash: number;
  #key: ReturnType<typeof parsePassportKey>;
  #reader?: PassportAAReader;

  private constructor(spki: Buffer, ecdsaHash: number, encryptionPublicKey: Buffer) {
    super();
    this.#key = parsePassportKey(spki, ecdsaHash);
    this.ecdsaHash = ecdsaHash;
    this.authType = "PassportActiveAuthentication";
    this.capability = "public";
    this.signer = { publicKey: spki };
    this.cypher = { publicKey: encryptionPublicKey };
  }

  static fromPassport({ dg15, dg14, reader, encryptionSecretKey }: PassportAAOptions) {
    if (typeof reader !== "function") throw new Error("A passport AA reader is required");
    const spki = readDG15(dg15);
    const hashId = dg14 === undefined ? 0 : readDG14Hash(dg14);
    const secretKey = requireBytes(encryptionSecretKey, "X25519 secret key", 32);
    const cypher = nacl.box.keyPair.fromSecretKey(secretKey);
    const manager = new PassportAAManager(spki, hashId, Buffer.from(cypher.publicKey));
    manager.cypher.secretKey = secretKey;
    manager.#reader = reader;
    manager.capability = "private";
    return manager;
  }

  static fromId(id: Buffer) {
    if (id.length > 1100) throw new Error("Passport AA identity is too large");
    const { v, x, e, h } = decodeRecord(id, "passport AA identity");
    if (v !== 1 || typeof h !== "number" || !Number.isInteger(h)) throw new Error("Invalid passport AA identity parameters");
    const manager = new PassportAAManager(requireBytes(x, "passport AA public key"), h, requireBytes(e, "X25519 public key", 32));
    if (!manager.id.equals(id)) throw new Error("Passport AA identity must use canonical serialization");
    return manager;
  }

  static instantiate(stored: PassportAAManager) {
    return new PassportAAManager(requireBytes(stored.signer.publicKey, "passport AA public key"), stored.ecdsaHash, requireBytes(stored.cypher.publicKey, "X25519 public key", 32));
  }

  get id() {
    return Buffer.from(encode({ v: 1, x: this.signer.publicKey, e: this.cypher.publicKey, h: this.ecdsaHash }));
  }

  copyForProtocol() {
    const copy = PassportAAManager.fromId(this.id);
    if (this.#reader && this.cypher.secretKey) {
      copy.#reader = this.#reader;
      copy.cypher.secretKey = Buffer.from(this.cypher.secretKey);
      copy.capability = "private";
    }
    return copy;
  }

  getSecret(): Buffer {
    throw new Error("Cannot export the secret of a passport AA identity");
  }

  cleanSecureData() {
    this.#reader = undefined;
    this.capability = "public";
    super.cleanSecureData();
  }

  private challenges(digest: Buffer, salt: Buffer) {
    const identityDigest = hash("sha256", Buffer.concat([Buffer.from([TYPE_PASSPORT_AA]), this.id]));
    const combined = hash("sha256", Buffer.concat([DOMAIN, identityDigest, digest, salt]));
    return Array.from({ length: CHALLENGE_COUNT }, (_, i) => combined.slice(i * CHALLENGE_BYTES, (i + 1) * CHALLENGE_BYTES));
  }

  private distinct(challenges: Buffer[]) {
    return new Set(challenges.map((challenge) => challenge.toString("hex"))).size === CHALLENGE_COUNT;
  }

  async getSigner() {
    return {
      sign: async (digest: Buffer) => {
        const reader = this.#reader;
        if (!reader) return null;
        const data = requireBytes(digest, "passport AA domain digest", DIGEST_BYTES);
        let salt: Buffer;
        let challenges: Buffer[];
        do {
          salt = randomBytes(DIGEST_BYTES);
          challenges = this.challenges(data, salt);
        } while (!this.distinct(challenges));
        const responses = await reader(
          challenges.map((challenge) => Buffer.from(challenge)),
          this.#key.size,
        );
        if (!this.#reader) return null;
        if (!Array.isArray(responses) || responses.length !== CHALLENGE_COUNT) throw new Error("Expected four passport AA responses");
        const signature = Buffer.concat([salt, ...responses.map((response) => requireBytes(response, "passport AA response", this.#key.size))]);
        if (!this.verify(data, signature)) throw new Error("Passport AA response does not match the registered key and challenge");
        return signature;
      },
    };
  }

  verify(digest: Buffer, signature: Buffer) {
    if (digest.length !== DIGEST_BYTES || signature.length !== DIGEST_BYTES + CHALLENGE_COUNT * this.#key.size) return false;
    try {
      const challenges = this.challenges(digest, signature.slice(0, DIGEST_BYTES));
      if (!this.distinct(challenges)) return false;
      return challenges.every((challenge, i) => {
        const start = DIGEST_BYTES + i * this.#key.size;
        return this.#key.verify(challenge, signature.slice(start, start + this.#key.size));
      });
    } catch {
      return false;
    }
  }
}
