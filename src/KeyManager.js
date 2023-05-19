import { dearmorAndDecrypt, encryptAndArmor } from "@samuelthomas2774/saltpack";
import bip32ed25519 from "@stricahq/bip32ed25519";
const { Bip32PrivateKey, Bip32PublicKey } = bip32ed25519;
import msgpack from "@ygoe/msgpack";
import { hash, randomBytes } from "./crypto.js";
import nacl from "tweetnacl";

const LEVEL_ROOT = 1;
const LEVEL_DERIVED = 2;

const sha512 = (data) => hash("sha512", data);
const sha256 = (data) => hash("sha256", data);

export const derivePath = (node, path) => {
  let result = node;
  if (path.startsWith("m/")) path = path.slice(2);
  path.split("/").forEach((d) => {
    if (d[d.length - 1] == "'")
      result = result.derive(
        2147483648 + parseInt(d.substring(0, d.length - 1)),
      );
    else result = result.derive(parseInt(d));
  });
  return result;
};

export default class KeyManager {
  constructor() {
    this.level = null; // ROOT, DERIVED
    this.capability = null; // private, public
    this.entropy = null;
    this.proof = null;
    this.proofPublicKey = null;
    this.signer = null;
    this.authType = "Ed25519VerificationKey2020";
    this.cypher = null;
    this.encType = "X25519KeyAgreementKey2019";
    this.swapIndex = 0;
  }

  static async create_Id25519_fromEntropy(entropy, swapIndex = 0) {
    const km = new KeyManager();
    km.entropy = entropy;
    km.level = LEVEL_ROOT;
    km.capability = "private";
    const seed = sha512(entropy);
    km.proofSigner = derivePath(
      await Bip32PrivateKey.fromEntropy(seed.slice(0, 32)),
      `m/1'/0'/${swapIndex}'`,
    );
    km.swapIndex = swapIndex;
    km.proof = hash("sha256", km.proofSigner.toBip32PublicKey().toBytes());
    const privateKey = derivePath(km.proofSigner, "/0'");
    km.signer = {
      publicKey: privateKey.toBip32PublicKey().toPublicKey().toBytes(),
      secretKey: privateKey.toBytes(),
    };
    const swapIndexBuffer = Buffer.alloc(8);
    swapIndexBuffer.writeBigInt64LE(BigInt(swapIndex));
    const seed2 = sha256(Buffer.concat([seed.slice(32, 64), swapIndexBuffer]));
    km.cypher = nacl.box.keyPair.fromSecretKey(seed2);
    km.cypher.publicKey = Buffer.from(km.cypher.publicKey);
    km.cypher.secretKey = Buffer.from(km.cypher.secretKey);
    return km;
  }

  static generate_Id25519() {
    return KeyManager.create_Id25519_fromEntropy(randomBytes(32));
  }

  get id() {
    return Buffer.from(
      msgpack.serialize({
        v: 0,
        p: this.proof,
        x: this.signer.publicKey,
        e: this.cypher.publicKey,
      }),
    );
  }


  getSecret() {
    return Buffer.from(
      msgpack.serialize({
        v: 0,
        p: this.proof,
        x: this.signer.secretKey,
        e: this.cypher.secretKey,
      }),
    );
  }

  static fromSecret(secret) {
    const data = msgpack.deserialize(secret);
    const km = new KeyManager();
    km.level = LEVEL_DERIVED;
    km.capability = "private";
    km.proof = data.p;
    km.signer = {
      secretKey: data.x,
      publicKey: new Bip32PrivateKey(data.x)
        .toBip32PublicKey()
        .toPublicKey()
        .toBytes(),
    };
    km.cypher = nacl.box.keyPair.fromSecretKey(data.e);
    km.cypher.secretKey = Buffer.from(km.cypher.secretKey);
    km.cypher.publicKey = Buffer.from(km.cypher.publicKey);
    return km;
  }

  static instantiate(obj) {
    const km = new KeyManager();
    km.level = obj.level;
    km.type = obj.type;
    km.proof = obj.proof.data
      ? Buffer.from(obj.proof.data)
      : Buffer.from(obj.proof);
    km.signer = {
      publicKey: obj.signer.publicKey.data
        ? Buffer.from(obj.signer.publicKey.data)
        : Buffer.from(obj.signer.publicKey),
    };
    km.cypher = {
      publicKey: obj.cypher.publicKey.data
        ? Buffer.from(obj.cypher.publicKey.data)
        : Buffer.from(obj.cypher.publicKey),
    };
    return km;
  }

  static fromId(id) {
    const data = msgpack.deserialize(id);
    const km = new KeyManager();
    km.level = LEVEL_DERIVED;
    km.capability = "public";
    km.proof = data.p;
    km.signer = {
      publicKey: data.x,
    };
    km.cypher = {
      publicKey: data.e,
    };
    return km;
  }

  sign(data) {
    if (this.capability == "public") return null;
    return new Bip32PrivateKey(this.signer.secretKey).toPrivateKey().sign(data);
  }

  verify(data, signature, userVerificationIgnored) {
    return Bip32PublicKey.fromBytes(this.signer.publicKey)
      .toPublicKey()
      .verify(signature, data);
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
    if (this.level === LEVEL_ROOT) {
      const newKey = await KeyManager.create_Id25519_fromEntropy(
        this.entropy,
        this.swapIndex + 1,
      );
      const proofKey = this.proofSigner
        .toBip32PublicKey()
        .toPublicKey()
        .toBytes();
      const hiscp = {
        newId: newKey.id,
        proofKey,
        timestamp: Date.now(),
      };
      const timestampBuffer = Buffer.alloc(8);
      timestampBuffer.writeBigUInt64LE(BigInt(hiscp.timestamp));
      const hiscpBuffer = Buffer.concat([
        hiscp.newId,
        hiscp.proofKey,
        timestampBuffer,
      ]);
      hiscp.signature = this.proofSigner.toPrivateKey().sign(hiscpBuffer);
      return hiscp;
    }
    return null;
  }

  async verifySwapingCertificate(hiscp) {
    const proof = hash("sha256", hiscp.proofKey).toString("hex");
    if (proof === this.proof.toString("hex")) {
      const timestampBuffer = Buffer.alloc(8);
      timestampBuffer.writeBigUInt64LE(BigInt(hiscp.timestamp));
      const newKey = KeyManager.fromId(hiscp.newId);
      const hiscpBuffer = Buffer.concat([
        hiscp.newId,
        hiscp.proofKey,
        timestampBuffer,
      ]);
      const proofVerifier = Bip32PublicKey.fromBytes(hiscp.proofKey);
      return proofVerifier.verify(hiscpBuffer, hiscp.signature);
    } else {
      return false;
    }
  }

  async encrypt(plaintext, recipientIds) {
    if (this.capability == "public") return null;
    const publicKeys = recipientIds
      .map(KeyManager.fromId)
      .map((km) => km.cypher.publicKey);
    return await encryptAndArmor(plaintext, this.cypher, publicKeys);
  }

  async decrypt(encryptedMessage, senderId = null) {
    if (this.capability == "public") return null;
    const senderKey = senderId
      ? KeyManager.fromId(senderId).cypher.publicKey
      : null;
    const message = await dearmorAndDecrypt(
      encryptedMessage,
      this.cypher,
      senderKey,
    );
    return message.toString();
  }

  // use better hash to prevent attack
  getSecretHash(data) {
    const toHash = Buffer.concat([
      data,
      Buffer.from("secrethash"),
      this.cypher.secretKey,
    ]);
    return hash("sha256", toHash);
  }
}
