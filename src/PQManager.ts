import { hash, randomBytes } from "./crypto";

import { Buffer } from "buffer/";
import nacl from "tweetnacl";
import { decode, encode } from "@msgpack/msgpack";
import { generateDilithiumKeyPair, signDilithium, verifyDilithium } from "./pqCrypto";
import KeyManager from "./KeyManager";

const LEVEL_ROOT = 1;
const LEVEL_DERIVED = 2;

const sha512 = (data: Buffer) => hash("sha512", data);
const sha256 = (data: Buffer) => hash("sha256", data);

export type KeyPair = {
  publicKey: Buffer;
  secretKey?: Buffer;
};

type DataExport = {
  v: 0; // version
  p: Buffer; // proof
  x: Buffer; // signing
  e: Buffer; // encrypting
};

type SecretExport = {
  v: 0; // version
  p: Buffer; // proof
  s: Buffer; // seed for signing and cypher
};

export default class PQManager extends KeyManager {
  seed?: Buffer;

  constructor() {
    super();
    this.authType = "DilithiumVerificationKey2025";
  }

  static async create_PQ_fromEntropy(entropy: Buffer, swapIndex = 0) {
    const km = new PQManager();
    km.entropy = entropy;
    km.level = LEVEL_ROOT;
    km.capability = "private";
    km.seed = sha512(entropy);
    km.swapIndex = swapIndex;
    km.proof = hash("sha256", Buffer.from([]));
    km.signer = generateDilithiumKeyPair(km.seed.slice(0, 32));
    const seed2 = sha256(km.seed.slice(32, 64));
    const cypher = nacl.box.keyPair.fromSecretKey(seed2);
    km.cypher = {
      publicKey: Buffer.from(cypher.publicKey),
      secretKey: Buffer.from(cypher.secretKey),
    };
    return km;
  }

  static generate_PQ() {
    return PQManager.create_PQ_fromEntropy(randomBytes(32));
  }

  getSecret() {
    return Buffer.from(
      encode({
        v: this.version,
        p: this.proof,
        s: this.seed,
      }),
    );
  }

  static fromSecret(secret: Buffer) {
    const data = decode(secret) as SecretExport;
    const km = new PQManager();
    km.version = data.v ?? 0;
    km.level = LEVEL_DERIVED;
    km.capability = "private";
    km.proof = data.p;
    km.seed = Buffer.from(data.s);
    km.signer = generateDilithiumKeyPair(km.seed.slice(0, 32));
    const seed2 = sha256(km.seed.slice(32, 64));
    const cypher = nacl.box.keyPair.fromSecretKey(seed2);
    km.cypher = {
      publicKey: Buffer.from(cypher.publicKey),
      secretKey: Buffer.from(cypher.secretKey),
    };
    return km;
  }

  static instantiate(obj: any) {
    const km = new PQManager();
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
    const km = new PQManager();
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
    return signDilithium(data, this.signer.secretKey!);
  }

  verify(data: Buffer, signature: Buffer, userVerificationIgnored?: boolean): boolean {
    return verifyDilithium(data, signature, this.signer.publicKey);
  }
}
