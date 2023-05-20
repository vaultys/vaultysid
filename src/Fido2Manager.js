import { hash, randomBytes } from "./crypto.js";
import { dearmorAndDecrypt, encryptAndArmor } from "@samuelthomas2774/saltpack";
import cbor from "cbor";
import nacl from "tweetnacl";
import msgpack from "@ygoe/msgpack";
import SoftCredentials from "./SoftCredentials.js";

const sha512 = (data) => hash("sha512", data);
const sha256 = (data) => hash("sha256", data);
const lookup = {
  usb: 1,
  nfc: 2,
  ble: 4,
  hybrid: 8,
};
const getTransports = (num) =>
  Object.keys(lookup).filter((i) => num & lookup[i]);
const fromTransports = (transports) =>
  transports.reduceRight((memo, i) => memo + (lookup[i] ? lookup[i] : 0), 0);

export default class Fido2Manager {
  constructor() {
    this.level = 1; // ROOT, no Proof Management
    this.capability = null; // private, public
    this.entropy = null;
    this.fid = null;
    this.t = null;
    this.ckey = null;
    this.cypher = null;
    this.encType = "X25519KeyAgreementKey2019";
  }

  get authType() {
    const type = cbor.decode(this.ckey).get(1);
    if (type === 1) {
      return "Ed25519VerificationKey2020";
    } else if (type === 2) {
      return "P256VerificationKey2020";
    } else return "Unknown";
  }

  get transports() {
    return getTransports(this.t);
  }

  static async createFromAttestation(attestation) {
    const f2m = new Fido2Manager();
    f2m.ckey = SoftCredentials.getCOSEPublicKey(attestation);
    f2m.fid = attestation.id;
    // fix for firefox, getTransports not available ! https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAttestationResponse/getTransports
    const transports = attestation.response.getTransports
      ? attestation.response.getTransports()
      : ["usb"];
    f2m.t = fromTransports(transports);
    const entropy = randomBytes(32);
    const seed = sha512(entropy, "hex");
    f2m.cypher = nacl.box.keyPair.fromSecretKey(seed.slice(0, 32));
    f2m.cypher.publicKey = Buffer.from(f2m.cypher.publicKey);
    f2m.cypher.secretKey = Buffer.from(f2m.cypher.secretKey);
    f2m.entropy = entropy;
    return f2m;
  }

  get signer() {
    return {
      publicKey: cbor.decode(this.ckey).get(-2),
    };
  }

  get id() {
    return Buffer.from(
      msgpack.serialize({
        v: 0,
        c: this.ckey,
        e: this.cypher.publicKey,
      }),
    );
  }

  getSecret() {
    return Buffer.from(
      msgpack.serialize({
        v: 1,
        f: this.fid,
        t: this.t,
        c: this.ckey,
        e: this.cypher.secretKey,
      }),
    );
  }

  static fromSecret(secret) {
    const data = msgpack.deserialize(secret);
    const f2m = new Fido2Manager();
    f2m.capability = "private";
    f2m.fid = data.f;
    f2m.t = data.t ? data.t : 15;
    f2m.ckey = data.c;
    f2m.cypher = nacl.box.keyPair.fromSecretKey(data.e);
    f2m.cypher.secretKey = Buffer.from(f2m.cypher.secretKey);
    f2m.cypher.publicKey = Buffer.from(f2m.cypher.publicKey);
    return f2m;
  }

  static instantiate(obj) {
    const f2m = new Fido2Manager();
    f2m.level = obj.level;
    f2m.type = obj.type;
    f2m.fid = obj.fid;
    f2m.t = obj.t ? obj.t : 15;
    f2m.ckey = obj.ckey.data
      ? Buffer.from(obj.ckey.data)
      : Buffer.from(obj.ckey);
    f2m.cypher = {
      publicKey: obj.cypher.publicKey.data
        ? Buffer.from(obj.cypher.publicKey.data)
        : Buffer.from(obj.cypher.publicKey),
    };
    return f2m;
  }

  static fromId(id) {
    const data = msgpack.deserialize(id);
    const f2m = new Fido2Manager();
    f2m.capability = "public";
    f2m.fid = data.f;
    f2m.ckey = data.c;
    f2m.cypher = {
      publicKey: data.e,
    };
    return f2m;
  }

  async sign(data) {
    if (this.capability == "public") return null;
    // need fido2 credentials mounted
    if (!navigator.credentials) return null;
    // ugly request userinteraction (needed for Safari and iOS)
    try {
      await CredentialUserInteractionRequest();
    } catch (error) {}
    const challenge = hash("sha256", data);
    const payload = {
      publicKey: {
        challenge,
        userVerification: "preferred",
        allowCredentials: [
          {
            type: "public-key",
            id: Buffer.from(this.fid, "base64"),
            transports: getTransports(this.t),
          },
        ],
      },
    };
    const assertion = await navigator.credentials.get(payload);
    //console.log(assertion)
    const response = {
      s: Buffer.from(assertion.response.signature),
      c: Buffer.from(assertion.response.clientDataJSON),
      a: Buffer.from(assertion.response.authenticatorData),
    };
    return Buffer.from(msgpack.encode(response));
  }

  verify(data, signature, userVerification) {
    const decoded = msgpack.decode(signature);
    const response = {
      signature: decoded.s,
      clientDataJSON: decoded.c,
      authenticatorData: decoded.a,
    };
    const challenge = hash("sha256", data).toString("base64");
    const extractedChallenge = SoftCredentials.extractChallenge(
      response.clientDataJSON,
    );
    if (challenge != extractedChallenge) {
      return false;
    }
    return SoftCredentials.simpleVerify(this.ckey, response, userVerification);
  }

  verifyCredentials(credentials, userVerification = false) {
    if (credentials.id !== this.fid) {
      return false;
    }
    const rpIdHash = credentials.response.authenticatorData
      .slice(0, 32)
      .toString("hex");
    const myIdHash = sha256(Buffer.from(credentials.id, "base64")).toString(
      "hex",
    );
    if (rpIdHash !== myIdHash) {
      return false;
    }
    return SoftCredentials.simpleVerify(
      this.ckey,
      credentials.response,
      userVerification,
    );
  }

  async createRevocationCertificate(newId) {
    // impossible
    return null;
  }

  async encrypt(plaintext, recipientIds) {
    if (this.capability == "public") return null;
    const publicKeys = recipientIds
      .map(Fido2Manager.fromId)
      .map((f2m) => f2m.cypher.publicKey);
    return await encryptAndArmor(plaintext, this.cypher, publicKeys);
  }

  async decrypt(encryptedMessage, senderId = null) {
    if (this.capability == "public") return null;
    const senderKey = senderId
      ? Fido2Manager.fromId(senderId).cypher.publicKey
      : null;
    const message = await dearmorAndDecrypt(
      encryptedMessage,
      this.cypher,
      senderKey,
    );
    return message.toString();
  }

  getSecretHash(data) {
    const toHash = Buffer.concat([
      data,
      Buffer.from("secrethash"),
      this.cypher.secretKey,
    ]);
    return hash("sha256", toHash);
  }
}
