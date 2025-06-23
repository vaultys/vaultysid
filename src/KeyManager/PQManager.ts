import { hash, randomBytes } from "../crypto";
import { Buffer } from "buffer/";
import nacl from "tweetnacl";
import { decode, encode } from "@msgpack/msgpack";
import { generateDilithiumKeyPair, signDilithium, verifyDilithium } from "../pqCrypto";
import CypherManager from "./CypherManager";

const sha512 = (data: Buffer) => hash("sha512", data);
const sha256 = (data: Buffer) => hash("sha256", data);

type DataExport = {
  v: 0; // version
  x: Buffer; // signing
  e: Buffer; // encrypting
};

type SecretExport = {
  v: 0; // version
  s: Buffer; // seed for signing and cypher
};

export default class PQManager extends CypherManager {
  seed?: Buffer;

  constructor() {
    super();
    this.authType = "DilithiumVerificationKey2025";
  }

  static async createFromEntropy(entropy: Buffer, swapIndex = 0) {
    const km = new PQManager();
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
    return PQManager.createFromEntropy(randomBytes(32));
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
    const km = new PQManager();
    km.version = data.v ?? 0;
    km.capability = "private";
    km.seed = Buffer.from(data.s);
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
    const km = new PQManager();
    km.version = obj.version ?? 0;
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
    km.capability = "public";
    km.signer = {
      publicKey: data.x,
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
    const secretKey = this.signer.secretKey!;
    const sign = (data: Buffer) => Promise.resolve(signDilithium(data, this.signer.secretKey!));
    return Promise.resolve({ sign });
  }

  verify(data: Buffer, signature: Buffer, userVerificationIgnored?: boolean): boolean {
    return verifyDilithium(data, signature, this.signer.publicKey);
  }
}
