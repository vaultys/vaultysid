import { hash, randomBytes } from "../crypto";
import { Buffer } from "buffer/";
import nacl from "tweetnacl";
import { decode, encode } from "@msgpack/msgpack";
import { generateDilithiumKeyPair, signDilithium, verifyDilithium } from "../pqCrypto";
import CypherManager from "./CypherManager";
import { decodeRecord, readVersion, requireBytes } from "./validation";
import { MLKEM768_PK_LENGTH } from "../pqCrypto";

export const DILITHIUM_PK_LENGTH = 2592;

const sha512 = (data: Buffer) => hash("sha512", data);

type DataExport = {
  v: 0 | 1; // version
  x: Buffer; // signing
  e: Buffer; // encrypting
  k?: Buffer; // ML-KEM-768 encapsulation key, post-quantum identities only
};

type SecretExport = {
  v: 0; // version
  s: Buffer; // seed for signing and cypher
};

export default class DilithiumManager extends CypherManager {
  seed?: Buffer;

  constructor() {
    super();
    this.authType = "DilithiumVerificationKey2025";
  }

  static async createFromEntropy(entropy: Buffer) {
    const km = new DilithiumManager();
    km.entropy = entropy;
    km.capability = "private";
    km.seed = sha512(entropy);
    km.signer = generateDilithiumKeyPair(km.seed.slice(0, 32));
    const cypher = nacl.box.keyPair.fromSecretKey(km.seed.slice(32, 64));
    km.cypher = {
      publicKey: Buffer.from(cypher.publicKey),
      secretKey: Buffer.from(cypher.secretKey),
    };
    return km;
  }

  static generate() {
    return DilithiumManager.createFromEntropy(randomBytes(32));
  }

  getSecret() {
    return Buffer.from(
      encode({
        v: this.version,
        s: this.seed,
      }),
    );
  }

  get id() {
    const data: DataExport = {
      v: this.version,
      x: this.signer.publicKey,
      e: this.cypher.publicKey,
    };
    if (this.kem) data.k = this.kem.publicKey;
    return Buffer.from(encode(data));
  }

  /**
   * Derive the ML-KEM-768 key pair and the PRF key from the seed, making this
   * the key manager of a post-quantum identity (rfc/PQ-ENCRYPTION.md §3).
   */
  enablePostQuantum() {
    if (!this.seed) throw new Error("a seed is required to derive post-quantum keys");
    this.derivePostQuantumKeys(this.seed);
    return this;
  }

  static fromSecret(secret: Buffer) {
    const data = decodeRecord(secret, "Dilithium secret");
    const km = new DilithiumManager();
    km.version = readVersion(data.v);
    km.capability = "private";
    km.seed = requireBytes(data.s, "Dilithium seed", 64);
    km.signer = generateDilithiumKeyPair(km.seed.slice(0, 32));
    const seed2 = km.seed.slice(32, 64);
    const cypher = nacl.box.keyPair.fromSecretKey(seed2);
    km.cypher = {
      publicKey: Buffer.from(cypher.publicKey),
      secretKey: Buffer.from(cypher.secretKey),
    };
    return km;
  }

  static instantiate(obj: any) {
    const km = new DilithiumManager();
    km.version = obj.version ?? 0;
    km.signer = {
      publicKey: obj.signer.publicKey.data ? Buffer.from(obj.signer.publicKey.data) : Buffer.from(obj.signer.publicKey),
    };
    km.cypher = {
      publicKey: obj.cypher.publicKey.data ? Buffer.from(obj.cypher.publicKey.data) : Buffer.from(obj.cypher.publicKey),
    };
    if (obj.kem?.publicKey) {
      km.kem = {
        publicKey: obj.kem.publicKey.data ? Buffer.from(obj.kem.publicKey.data) : Buffer.from(obj.kem.publicKey),
      };
    }
    return km;
  }

  static fromId(id: Buffer) {
    const data = decodeRecord(id, "Dilithium id");
    const km = new DilithiumManager();
    km.version = readVersion(data.v);
    km.capability = "public";
    km.signer = {
      publicKey: requireBytes(data.x, "Dilithium public key", DILITHIUM_PK_LENGTH),
    };
    km.cypher = {
      publicKey: requireBytes(data.e, "X25519 public key", 32),
    };
    if (data.k !== undefined) {
      km.kem = { publicKey: requireBytes(data.k, "ML-KEM-768 public key", MLKEM768_PK_LENGTH) };
    }
    return km;
  }

  getSigner(): Promise<{
    sign: (data: Buffer) => Promise<Buffer | null>;
  }> {
    // todo fetch secretKey here
    const secretKey = this.signer.secretKey!;
    const sign = (data: Buffer) => Promise.resolve(signDilithium(data, this.signer.secretKey!));
    return Promise.resolve({ sign });
  }

  verify(data: Buffer, signature: Buffer, userVerificationIgnored?: boolean): boolean {
    try {
      return verifyDilithium(data, signature, this.signer.publicKey);
    } catch {
      return false;
    }
  }
}
