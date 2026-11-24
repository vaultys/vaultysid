import { hash, randomBytes, secureErase } from "../crypto";
import { Buffer } from "buffer/";
import nacl from "tweetnacl";
import { decode, encode } from "@msgpack/msgpack";
import { generateDilithiumKeyPair, signDilithium, verifyDilithium } from "../pqCrypto";
import CypherManager from "./CypherManager";
import { DILITHIUM_PK_LENGTH } from "./DilithiumManager";
import { decodeRecord, readVersion, requireBytes } from "./validation";
import { MLKEM768_PK_LENGTH } from "../pqCrypto";
import { KeyPair } from ".";
import { ed25519 } from "@noble/curves/ed25519.js";

const sha512 = (data: Buffer) => hash("sha512", data);

type DataExport = {
  v: 0 | 1; // version
  x: Buffer; // signing
  e: Buffer; // encrypting
  k?: Buffer; // ML-KEM-768 encapsulation key, post-quantum identities only
};

type SecretExport = {
  v: 0; // version
  alg: "hybrid"; // flag for hybrid cryptography
  s: Buffer; // seed for signing and cypher
};

export default class HybridManager extends CypherManager {
  seed?: Buffer;
  pqSigner?: KeyPair;
  edSigner?: KeyPair;

  constructor() {
    super();
    this.authType = "DilithiumEdDSAVerificationKey2025";
  }

  static async createFromEntropy(entropy: Buffer) {
    const km = new HybridManager();
    km.entropy = entropy;
    km.capability = "private";
    km.seed = sha512(entropy);
    const signerSeed = sha512(km.seed.slice(0, 32));
    km.pqSigner = generateDilithiumKeyPair(signerSeed.slice(0, 32));
    km.edSigner = {
      publicKey: Buffer.from(ed25519.getPublicKey(signerSeed.slice(32, 64))),
      secretKey: signerSeed.slice(32, 64),
    };
    km.signer = {
      publicKey: Buffer.concat([km.edSigner.publicKey, km.pqSigner.publicKey]),
      secretKey: Buffer.concat([km.edSigner.secretKey!, km.pqSigner.secretKey!]),
    };
    const cypher = nacl.box.keyPair.fromSecretKey(km.seed.slice(32, 64));
    km.cypher = {
      publicKey: Buffer.from(cypher.publicKey),
      secretKey: Buffer.from(cypher.secretKey),
    };
    return km;
  }

  static generate() {
    return HybridManager.createFromEntropy(randomBytes(32));
  }

  getSecret() {
    return Buffer.from(
      encode({
        v: this.version,
        alg: "hybrid",
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
    const data = decodeRecord(secret, "Hybrid secret");
    if (data.alg !== "hybrid") throw new Error("Not a secret for Hybrid Cryptography");
    const km = new HybridManager();
    km.version = readVersion(data.v);
    km.capability = "private";
    km.seed = requireBytes(data.s, "Hybrid seed", 64);
    const signerSeed = sha512(km.seed.slice(0, 32));
    km.pqSigner = generateDilithiumKeyPair(signerSeed.slice(0, 32));
    km.edSigner = {
      publicKey: Buffer.from(ed25519.getPublicKey(signerSeed.slice(32, 64))),
      secretKey: signerSeed.slice(32, 64),
    };
    km.signer = {
      publicKey: Buffer.concat([km.edSigner.publicKey, km.pqSigner.publicKey]),
      secretKey: Buffer.concat([km.edSigner.secretKey!, km.pqSigner.secretKey!]),
    };
    //km.signer = generateDilithiumKeyPair(km.seed.slice(0, 32));
    const cypher = nacl.box.keyPair.fromSecretKey(km.seed.slice(32, 64));
    km.cypher = {
      publicKey: Buffer.from(cypher.publicKey),
      secretKey: Buffer.from(cypher.secretKey),
    };
    return km;
  }

  static instantiate(obj: any) {
    const km = new HybridManager();
    km.version = obj.version ?? 0;
    km.signer = {
      publicKey: obj.signer.publicKey.data ? Buffer.from(obj.signer.publicKey.data) : Buffer.from(obj.signer.publicKey),
    };
    km.edSigner = {
      publicKey: km.signer.publicKey.slice(0, 32),
    };
    km.pqSigner = {
      publicKey: km.signer.publicKey.slice(32),
    };
    km.cypher = {
      publicKey: obj.cypher.publicKey.data ? Buffer.from(obj.cypher.publicKey.data) : Buffer.from(obj.cypher.publicKey),
    };
    if (obj.kem?.publicKey) {
      km.kem = {
        publicKey: obj.kem.publicKey.data ? Buffer.from(obj.kem.publicKey.data) : Buffer.from(obj.kem.publicKey),
      };
    }
    km.capability = "public"; // instantiated from stored public data only
    return km;
  }

  cleanSecureData() {
    for (const secret of [this.seed, this.edSigner?.secretKey, this.pqSigner?.secretKey, this.signer?.secretKey]) {
      if (secret) secureErase(secret);
    }
    delete this.seed;
    if (this.edSigner) delete this.edSigner.secretKey;
    if (this.pqSigner) delete this.pqSigner.secretKey;
    if (this.signer) delete this.signer.secretKey;
    this.capability = "public";
    super.cleanSecureData();
  }

  static fromId(id: Buffer) {
    const data = decodeRecord(id, "Hybrid id");
    const x = requireBytes(data.x, "Hybrid public key", 32 + DILITHIUM_PK_LENGTH);
    const km = new HybridManager();
    km.version = readVersion(data.v);
    km.capability = "public";
    km.signer = {
      publicKey: x,
    };
    km.edSigner = {
      publicKey: x.slice(0, 32),
    };
    km.pqSigner = {
      publicKey: x.slice(32),
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
    const sign = (data: Buffer) => {
      const sign1 = ed25519.sign(data, this.edSigner!.secretKey!);
      const sign2 = signDilithium(Buffer.concat([data, sign1]), this.pqSigner!.secretKey!);
      return Promise.resolve(Buffer.concat([sign1, sign2]));
    };
    return Promise.resolve({ sign });
  }

  verify(data: Buffer, signature: Buffer, userVerificationIgnored?: boolean): boolean {
    try {
      if (!signature || signature.length <= 64) return false;
      const sign1 = signature.slice(0, 64);
      const sign2 = signature.slice(64);
      const verify1 = ed25519.verify(sign1, data, this.edSigner!.publicKey);
      if (!verify1) return false;
      return verifyDilithium(Buffer.concat([data, sign1]), sign2, this.pqSigner!.publicKey);
    } catch {
      return false;
    }
  }
}
