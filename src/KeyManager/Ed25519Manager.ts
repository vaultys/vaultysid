import { dearmorAndDecrypt, encryptAndArmor } from "@vaultys/saltpack";
import { hash, hmac, randomBytes, secureErase } from "../crypto";
import { Buffer } from "buffer/";
import nacl, { BoxKeyPair } from "tweetnacl";
import { decode, encode } from "@msgpack/msgpack";
import { ed25519 } from "@noble/curves/ed25519";
import { KeyPair } from "./";
import CypherManager from "./CypherManager";

ed25519.CURVE = { ...ed25519.CURVE };
// @ts-ignore hack to get compatibility with former @stricahq/bip32ed25519 lib
ed25519.CURVE.adjustScalarBytes = (bytes: Uint8Array): Uint8Array => {
  // Section 5: For X25519, in order to decode 32 random bytes as an integer scalar,
  // set the three least significant bits of the first byte
  bytes[0] &= 248; // 0b1111_1000
  // and the most significant bit of the last to zero,
  bytes[31] &= 63; // 0b0001_1111
  // set the second most significant bit of the last byte to 1
  bytes[31] |= 64; // 0b0100_0000
  return bytes;
};

const serializeID_v0 = (km: Ed25519Manager) => {
  const encodeBinary = (data: Buffer): Buffer => {
    if (data.length <= 65535) {
      // bin16: binary data whose length is upto (2^16)-1 bytes
      return Buffer.from([0xc5, data.length >> 8, data.length & 0xff, ...data]);
    } else {
      // bin32: binary data whose length is upto (2^32)-1 bytes
      return Buffer.from([0xc6, (data.length >> 24) & 0xff, (data.length >> 16) & 0xff, (data.length >> 8) & 0xff, data.length & 0xff, ...data]);
    }
  };

  const version = Buffer.from([0x84, 0xa1, 0x76, 0]);
  const proof = Buffer.concat([Buffer.from([0xa1, 0x70]), encodeBinary(Buffer.from([]))]);
  const sign = Buffer.concat([Buffer.from([0xa1, 0x78]), encodeBinary(km.signer.publicKey)]);
  const cypher = Buffer.concat([Buffer.from([0xa1, 0x65]), encodeBinary(km.cypher.publicKey)]);
  return Buffer.concat([version, proof, sign, cypher]);
};

const sha512 = (data: Buffer) => hash("sha512", data);
const sha256 = (data: Buffer) => hash("sha256", data);

type DataExport = {
  v: 0; // version
  x: Buffer; // signing secretKey or publicKey
  e: Buffer; // encrypting secretKey or publicKey
};

export default class Ed25519Manager extends CypherManager {
  version: 0 | 1 = 1;
  capability: "private" | "public" = "private";
  entropy: Buffer | undefined;
  signer!: KeyPair;

  constructor() {
    super();
    this.authType = "Ed25519VerificationKey2020";
  }

  static async createFromEntropy(entropy: Buffer) {
    const km = new Ed25519Manager();
    km.entropy = entropy;
    km.capability = "private";
    const seed = sha512(entropy);
    // const derivedKey = privateDerivePath(await bip32.Bip32PrivateKey.fromEntropy(seed.slice(0, 32)), `m/1'/0'/${swapIndex}'`);
    // km.proofKey = {
    //   publicKey: Buffer.from([]), //deprecated
    // };
    //km.proof = hash("sha256", km.proofKey.publicKey);
    // const privateKey = privateDerivePath(derivedKey, "/0'");
    km.signer = {
      publicKey: Buffer.from(ed25519.getPublicKey(seed.slice(0, 32))),
      secretKey: seed.slice(0, 32),
    };
    const cypher = nacl.box.keyPair.fromSecretKey(seed.slice(32, 64));
    km.cypher = {
      publicKey: Buffer.from(cypher.publicKey),
      secretKey: Buffer.from(cypher.secretKey),
    };
    return km;
  }

  static generate() {
    return Ed25519Manager.createFromEntropy(randomBytes(32));
  }

  get id() {
    if (this.version === 0) return serializeID_v0(this);
    else
      return Buffer.from(
        encode({
          v: this.version,
          x: this.signer.publicKey,
          e: this.cypher.publicKey,
        }),
      );
  }

  async getCypher() {
    // todo fetch secretKey here
    const cypher = this.cypher;
    return {
      hmac: (message: string) => (cypher.secretKey ? hmac("sha256", Buffer.from(cypher.secretKey), "VaultysID/" + message + "/end") : undefined),
      signcrypt: async (plaintext: string, publicKeys: Buffer[]) => encryptAndArmor(plaintext, cypher as BoxKeyPair, publicKeys),
      decrypt: async (encryptedMessage: string, senderKey?: Buffer | null) => dearmorAndDecrypt(encryptedMessage, cypher as BoxKeyPair, senderKey),
      diffieHellman: async (publicKey: Buffer) => Buffer.from(nacl.scalarMult(cypher.secretKey!, publicKey)),
    };
  }

  getSigner(): Promise<{
    sign: (data: Buffer) => Promise<Buffer | null>;
  }> {
    // todo fetch secretKey here
    const secretKey = this.signer.secretKey!;
    const sign = (data: Buffer) => Promise.resolve(Buffer.from(ed25519.sign(data, secretKey)));
    //console.log(secretKey.toString("hex"), new bip32.PrivateKey(secretKey).toPublicKey().toBytes().toString("hex"), Buffer.from(ed25519.getPublicKey(secretKey)).toString("hex"));
    return Promise.resolve({ sign });
  }

  getSecret() {
    return Buffer.from(
      encode({
        v: this.version,
        x: this.signer.secretKey,
        e: this.cypher.secretKey,
      }),
    );
  }

  static fromSecret(secret: Buffer) {
    const data = decode(secret) as DataExport;
    const km = new Ed25519Manager();
    km.version = data.v ?? 0;
    km.capability = "private";
    km.signer = {
      secretKey: data.x.slice(0, 32),
      publicKey: Buffer.from(ed25519.getPublicKey(data.x.slice(0, 32))),
    };
    const cypher = nacl.box.keyPair.fromSecretKey(data.e);
    km.cypher = {
      publicKey: Buffer.from(cypher.publicKey),
      secretKey: Buffer.from(cypher.secretKey),
    };
    return km;
  }

  static instantiate(obj: any) {
    const km = new Ed25519Manager();
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
    const km = new Ed25519Manager();
    km.version = data.v ?? 0;
    km.capability = "public";
    km.signer = {
      publicKey: data.x,
    };
    km.cypher = {
      publicKey: data.e,
    };
    return km;
  }

  verify(data: Buffer, signature: Buffer, userVerificationIgnored?: boolean): boolean {
    return ed25519.verify(signature, data, this.signer.publicKey);
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
}
