import { dearmorAndDecrypt, encryptAndArmor } from "@samuelthomas2774/saltpack";
import { hash, randomBytes, secureErase } from "./crypto";
import { Buffer } from "buffer";
import nacl, { BoxKeyPair } from "tweetnacl";
import { decode, encode } from "@msgpack/msgpack";
import * as bip32fix from "@stricahq/bip32ed25519";
import { createHmac } from "crypto";

//@ts-expect-error fix for wrong way of exporting bip32ed25519
const bip32 = bip32fix.default ?? bip32fix;

const LEVEL_ROOT = 1;
const LEVEL_DERIVED = 2;

const sha512 = (data: Buffer) => hash("sha512", data);
const sha256 = (data: Buffer) => hash("sha256", data);

const serializeID_v0 = (km: KeyManager) => {
  const version = Buffer.from([0x84, 0xa1, 0x76, 0]);
  const proof = Buffer.from([0xa1, 0x70, 0xc5, 0x00, km.proof.length, ...km.proof]);
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

export default class KeyManager {
  level: number = 1;
  version: 0 | 1 = 1;
  capability: "private" | "public" = "private";
  entropy: Buffer | undefined;
  proof!: Buffer;
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
    const km = new KeyManager();
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
    swapIndexBuffer.writeBigInt64LE(BigInt(swapIndex));
    const seed2 = sha256(Buffer.concat([seed.slice(32, 64), swapIndexBuffer]));
    const cypher = nacl.box.keyPair.fromSecretKey(seed2);
    km.cypher = {
      publicKey: Buffer.from(cypher.publicKey),
      secretKey: Buffer.from(cypher.secretKey),
    };
    return km;
  }

  static generate_Id25519() {
    return KeyManager.create_Id25519_fromEntropy(randomBytes(32));
  }

  get id() {
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
          ? createHmac("sha256", cypher.secretKey.toString("hex"))
              .update("VaultysID-" + message)
              .digest()
          : undefined,
      signcrypt: async (plaintext: string, publicKeys: Buffer[]) => encryptAndArmor(plaintext, cypher as BoxKeyPair, publicKeys),
      decrypt: async (encryptedMessage: string, senderKey?: Buffer | null) => dearmorAndDecrypt(encryptedMessage, cypher as BoxKeyPair, senderKey),
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
    const km = new KeyManager();
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
    const km = new KeyManager();
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
    const km = new KeyManager();
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
    return bip32.Bip32PublicKey.fromBytes(this.signer.publicKey).toPublicKey().verify(signature, data);
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
      const newKey = await KeyManager.create_Id25519_fromEntropy(this.entropy, this.swapIndex + 1);

      const hiscp: HISCP = {
        newId: newKey.id,
        proofKey: this.proofKey.publicKey,
        timestamp: Date.now(),
        signature: Buffer.from([]),
      };
      const timestampBuffer = Buffer.alloc(8);
      timestampBuffer.writeBigUInt64LE(BigInt(hiscp.timestamp));
      const hiscpBuffer = Buffer.concat([hiscp.newId, hiscp.proofKey, timestampBuffer]);
      hiscp.signature = new bip32.Bip32PrivateKey(this.proofKey.secretKey!).toPrivateKey().sign(hiscpBuffer);
      return hiscp;
    }
    return null;
  }

  async verifySwapingCertificate(hiscp: HISCP) {
    const proof = hash("sha256", hiscp.proofKey).toString("hex");
    if (proof === this.proof.toString("hex")) {
      const timestampBuffer = Buffer.alloc(8);
      timestampBuffer.writeBigUInt64LE(BigInt(hiscp.timestamp));
      const newKey = KeyManager.fromId(hiscp.newId);
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
