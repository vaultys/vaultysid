import { dearmorAndDecrypt, encryptAndArmor } from "@samuelthomas2774/saltpack";
import { hash, randomBytes } from "./crypto";
import { Buffer } from "buffer/";
import nacl, { BoxKeyPair } from "tweetnacl";
import { decode, encode } from "@msgpack/msgpack";
import { createHmac } from "crypto";
import { generateDilithiumKeyPair, signDilithium, verifyDilithium } from "./pqCrypto";
import KeyManager from "./KeyManager";
import { DilithiumLevel, DilithiumPrivateKey, DilithiumPublicKey } from "@asanrom/dilithium";

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
  x: Buffer; // signing secretKey or publicKey
  e: Buffer; // encrypting secretKey or publicKey
};

export default class PQManager extends KeyManager {
  constructor() {
    super();
    this.authType = "DilithiumVerificationKey2025";
  }

  static async create_PQ_fromEntropy(entropy: Buffer, swapIndex = 0) {
    const km = new PQManager();
    km.entropy = entropy;
    km.level = LEVEL_ROOT;
    km.capability = "private";
    const seed = sha512(entropy);
    km.swapIndex = swapIndex;
    km.proof = hash("sha256", Buffer.from([]));
    km.signer = generateDilithiumKeyPair(seed.slice(0, 32));
    const seed2 = sha256(seed.slice(32, 64));
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

  static fromSecret(secret: Buffer) {
    const data = decode(secret) as DataExport;
    const km = new PQManager();
    km.version = data.v ?? 0;
    km.level = LEVEL_DERIVED;
    km.capability = "private";
    km.proof = data.p;
    km.signer = {
      secretKey: data.x,
      publicKey: Buffer.from(DilithiumPrivateKey.fromBytes(data.x, DilithiumLevel.get(2)).derivePublicKey().getBytes()),
    };
    const cypher = nacl.box.keyPair.fromSecretKey(data.e);
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
