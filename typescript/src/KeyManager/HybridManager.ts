import { hash, randomBytes } from "../crypto";
import { Buffer } from "buffer/";
import nacl from "tweetnacl";
import { decode, encode } from "@msgpack/msgpack";
import { generateDilithiumKeyPair, signDilithium, verifyDilithium } from "../pqCrypto";
import CypherManager from "./CypherManager";
import { KeyPair } from ".";
import { ed25519 } from "@noble/curves/ed25519";

const sha512 = (data: Buffer) => hash("sha512", data);

type DataExport = {
  v: 0; // version
  x: Buffer; // signing
  e: Buffer; // encrypting
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
    return Buffer.from(
      encode({
        v: this.version,
        x: this.signer.publicKey,
        e: this.cypher.publicKey,
      }),
    );
  }

  static fromSecret(secret: Buffer) {
    const data = decode(secret) as SecretExport;
    if (data.alg !== "hybrid") throw new Error("Not a secret for Hybrid Cryptography");
    const km = new HybridManager();
    km.version = data.v ?? 0;
    km.capability = "private";
    km.seed = Buffer.from(data.s);
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
    return km;
  }

  static fromId(id: Buffer) {
    const data = decode(id) as DataExport;
    const km = new HybridManager();
    km.version = data.v ?? 0;
    km.capability = "public";
    km.signer = {
      publicKey: data.x,
    };
    km.edSigner = {
      publicKey: data.x.slice(0, 32),
    };
    km.pqSigner = {
      publicKey: data.x.slice(32),
    };
    km.cypher = {
      publicKey: data.e,
    };
    // console.log(km)
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
    const sign1 = signature.slice(0, 64);
    const sign2 = signature.slice(64);
    const verify1 = ed25519.verify(sign1, data, this.edSigner!.publicKey);
    if (!verify1) return false;
    return verifyDilithium(Buffer.concat([data, sign1]), sign2, this.pqSigner!.publicKey);
  }
}
