import { dearmorAndDecrypt, encryptAndArmor } from "@vaultys/saltpack";
import { hash, hmac, randomBytes, secureErase } from "../crypto";
import { Buffer } from "buffer/";
import nacl, { BoxKeyPair } from "tweetnacl";
import { decode, encode } from "@msgpack/msgpack";
import { ed25519 } from "@noble/curves/ed25519.js";
import { KeyPair } from "./";
import CypherManager from "./CypherManager";
import { decodeRecord, readVersion, requireBytes } from "./validation";
import type { Ed25519Signer } from "../Ed25519Signer";

// // @ts-ignore hack to get compatibility with former @stricahq/bip32ed25519 lib
// ed25519.CURVE = { ...ed25519.CURVE };
// // @ts-ignore hack to get compatibility with former @stricahq/bip32ed25519 lib
// ed25519.CURVE.adjustScalarBytes = (bytes: Uint8Array): Uint8Array => {
//   // Section 5: For X25519, in order to decode 32 random bytes as an integer scalar,
//   // set the three least significant bits of the first byte
//   bytes[0] &= 248; // 0b1111_1000
//   // and the most significant bit of the last to zero,
//   bytes[31] &= 63; // 0b0001_1111
//   // set the second most significant bit of the last byte to 1
//   bytes[31] |= 64; // 0b0100_0000
//   return bytes;
// };

const sha512 = (data: Buffer) => hash("sha512", data);

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
  #externalSigner?: Ed25519Signer;

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

  static async fromSigner(signer: Ed25519Signer, encryptionSecretKey: Uint8Array) {
    const publicKey = requireBytes(await signer.getPublicKey(), "Ed25519 public key", 32);
    const point = ed25519.Point.fromBytes(publicKey, false);
    if (point.isSmallOrder() || !point.isTorsionFree()) throw new Error("Invalid Ed25519 public key");

    const secretKey = requireBytes(encryptionSecretKey, "X25519 secret key", 32);
    const cypher = nacl.box.keyPair.fromSecretKey(secretKey);
    const km = new Ed25519Manager();
    km.signer = { publicKey };
    km.cypher = { publicKey: Buffer.from(cypher.publicKey), secretKey };
    km.#externalSigner = signer;
    return km;
  }

  /** @internal Copy an external signer for consumers that isolate serialization version. */
  copyWithExternalSigner() {
    if (!this.#externalSigner || this.capability === "public") return undefined;
    const copy = Ed25519Manager.fromId(this.id);
    const secretKey = this.cypher.secretKey;
    if (secretKey) copy.cypher.secretKey = Buffer.from(secretKey);
    copy.capability = "private";
    copy.#externalSigner = this.#externalSigner;
    return copy;
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
    const externalSigner = this.#externalSigner;
    if (externalSigner) {
      const canSign = () => this.capability === "private";
      return Promise.resolve({
        sign: async (data: Buffer) => {
          if (!canSign()) return null;
          const signature = requireBytes(await externalSigner.sign(Buffer.from(data)), "external Ed25519 signature", 64);
          if (!canSign()) return null;
          if (!this.verify(data, signature)) throw new Error("External Ed25519 signature did not verify for this identity");
          return signature;
        },
      });
    }
    // todo fetch secretKey here
    const secretKey = this.signer.secretKey!;
    const sign = (data: Buffer) => Promise.resolve(Buffer.from(ed25519.sign(data, secretKey)));
    //console.log(secretKey.toString("hex"), new bip32.PrivateKey(secretKey).toPublicKey().toBytes().toString("hex"), Buffer.from(ed25519.getPublicKey(secretKey)).toString("hex"));
    return Promise.resolve({ sign });
  }

  getSecret() {
    if (this.#externalSigner) throw new Error("Cannot export the secret of an externally signed identity");
    return Buffer.from(
      encode({
        v: this.version,
        x: this.signer.secretKey,
        e: this.cypher.secretKey,
      }),
    );
  }

  static fromSecret(secret: Buffer) {
    const data = decodeRecord(secret, "Ed25519 secret");
    const x = requireBytes(data.x, "Ed25519 signing secret key", 32);
    const e = requireBytes(data.e, "X25519 secret key", 32);
    const km = new Ed25519Manager();
    km.version = readVersion(data.v);
    km.capability = "private";
    km.signer = {
      secretKey: x,
      publicKey: Buffer.from(ed25519.getPublicKey(x)),
    };
    const cypher = nacl.box.keyPair.fromSecretKey(e);
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
    km.capability = "public"; // instantiated from stored public data only
    return km;
  }

  static fromId(id: Buffer) {
    const data = decodeRecord(id, "Ed25519 id");
    const km = new Ed25519Manager();
    km.version = readVersion(data.v);
    km.capability = "public";
    km.signer = {
      publicKey: requireBytes(data.x, "Ed25519 public key", 32),
    };
    km.cypher = {
      publicKey: requireBytes(data.e, "X25519 public key", 32),
    };
    return km;
  }

  verify(data: Buffer, signature: Buffer, userVerificationIgnored?: boolean): boolean {
    try {
      return ed25519.verify(signature, data, this.signer.publicKey);
    } catch {
      return false;
    }
  }

  cleanSecureData() {
    if (this.#externalSigner) this.capability = "public";
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
