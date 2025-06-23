import { hash, randomBytes } from "../crypto";
import cbor from "cbor";
import nacl from "tweetnacl";
import { getWebAuthnProvider, WebAuthnProvider } from "../platform/webauthn";
import { KeyPair } from ".";
import { decode, encode } from "@msgpack/msgpack";
import SoftCredentials from "../platform/SoftCredentials";
import { Buffer } from "buffer/";
import { PQ_COSE_ALG } from "../pqCrypto";
import CypherManager from "./CypherManager";

const sha512 = (data: Buffer) => hash("sha512", data);
const sha256 = (data: Buffer) => hash("sha256", data);

declare global {
  interface Window {
    CredentialUserInteractionRequest: () => Promise<void>;
  }
}

type Fido2Signature = {
  s: ArrayBuffer;
  c: ArrayBuffer;
  a: ArrayBuffer;
};

type ExportFIDO2Data = {
  v?: 0 | 1;
  f: Buffer | string;
  t: number;
  c: Buffer;
  e: Buffer;
};

type LookupType = "usb" | "nfc" | "ble" | "internal" | "hybrid" | "smart-card";

const lookup: Record<LookupType, number> = {
  usb: 1,
  nfc: 2,
  ble: 4,
  internal: 8,
  hybrid: 16,
  "smart-card": 32,
};

const encodeBinary = (data: Buffer): Buffer => {
  if (data.length <= 65535) {
    // bin16: binary data whose length is upto (2^16)-1 bytes
    return Buffer.from([0xc5, data.length >> 8, data.length & 0xff, ...data]);
  } else {
    // bin32: binary data whose length is upto (2^32)-1 bytes
    return Buffer.from([0xc6, (data.length >> 24) & 0xff, (data.length >> 16) & 0xff, (data.length >> 8) & 0xff, data.length & 0xff, ...data]);
  }
};

const serializeID_v0 = (km: Fido2Manager) => {
  const version = Buffer.from([0x83, 0xa1, 0x76, km.version]);
  const cypher = Buffer.concat([Buffer.from([0xa1, 0x65]), encodeBinary(km.cypher.publicKey)]);
  const ckey = Buffer.concat([Buffer.from([0xa1, 0x63]), encodeBinary(km.ckey)]);
  return Buffer.concat([version, ckey, cypher]);
};

const getTransports = (num: number) => Object.keys(lookup).filter((i) => num && lookup[i as LookupType]) as AuthenticatorTransport[];
const fromTransports = (transports: string[]): number => transports.reduceRight((memo, i) => memo + (lookup[i as LookupType] ? lookup[i as LookupType] : 0), 0);

const getAuthTypeFromCkey = (ckey: Buffer) => {
  const type = cbor.decode(ckey).get(1);
  if (type === 1) {
    return "Ed25519VerificationKey2020";
  } else if (type === 2) {
    return "P256VerificationKey2020";
  } else return "Unknown";
};

const getSignerFromCkey = (ckey: Buffer) => {
  const k = cbor.decode(ckey);
  let publicKey: Buffer = Buffer.from([]);
  if (k.get(3) == -7) publicKey = Buffer.concat([Buffer.from("04", "hex"), k.get(-2), k.get(-3)]);
  else if (k.get(3) == -8) publicKey = k.get(-2);
  else if (k.get(3) == PQ_COSE_ALG.DILITHIUM2) publicKey = k.get(-101);
  return { publicKey } as KeyPair;
};

export default class Fido2Manager extends CypherManager {
  webAuthn: WebAuthnProvider;
  fid!: Buffer;
  _transports: number = 0;
  ckey!: Buffer;

  constructor() {
    super();
    this.encType = "X25519KeyAgreementKey2019";
    this.webAuthn = getWebAuthnProvider();
  }

  get transports(): AuthenticatorTransport[] {
    return getTransports(this._transports) as AuthenticatorTransport[];
  }

  static async createFromAttestation(attestation: PublicKeyCredential) {
    const f2m = new Fido2Manager();
    f2m.ckey = SoftCredentials.getCOSEPublicKey(attestation)!;
    f2m.authType = getAuthTypeFromCkey(f2m.ckey);
    f2m.fid = Buffer.from(attestation.id, "base64");

    // fix for firefox, getTransports not available ! https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAttestationResponse/getTransports
    const response = attestation.response as AuthenticatorAttestationResponse;
    const transports = response.getTransports ? response.getTransports() : ["usb"];
    f2m._transports = fromTransports(transports);

    // signing
    f2m.signer = getSignerFromCkey(f2m.ckey);

    //encrypting
    const entropy = randomBytes(32);
    const seed = sha512(entropy);
    const cypher = nacl.box.keyPair.fromSecretKey(seed.slice(0, 32));
    f2m.cypher = {
      publicKey: Buffer.from(cypher.publicKey),
      secretKey: Buffer.from(cypher.secretKey),
    };

    f2m.entropy = entropy;
    return f2m;
  }

  get id() {
    if (this.version == 0) return serializeID_v0(this);
    else
      return Buffer.from(
        encode({
          v: this.version,
          c: this.ckey,
          e: this.cypher.publicKey,
        }),
      );
  }

  get id_v0() {
    return serializeID_v0(this);
  }

  getSecret() {
    return Buffer.from(
      encode({
        v: this.version,
        f: this.fid,
        t: this._transports,
        c: this.ckey,
        e: this.cypher.secretKey,
      }),
    );
  }

  static fromSecret(secret: Buffer) {
    const data = decode(secret) as ExportFIDO2Data;
    const f2m = new Fido2Manager();
    f2m.version = data.v ?? 0;
    f2m.capability = "private";
    f2m.fid = typeof data.f === "string" ? Buffer.from(data.f, "base64") : data.f;
    f2m._transports = data.t ? data.t : 15;
    f2m.ckey = data.c;
    f2m.authType = getAuthTypeFromCkey(f2m.ckey);
    f2m.signer = getSignerFromCkey(data.c);
    const cypher = nacl.box.keyPair.fromSecretKey(data.e);
    f2m.cypher = {
      publicKey: Buffer.from(cypher.publicKey),
      secretKey: Buffer.from(cypher.secretKey),
    };

    return f2m;
  }

  static instantiate(obj: any) {
    const f2m = new Fido2Manager();
    f2m.version = obj.version ?? 0;
    f2m.fid = typeof obj.fid === "string" ? Buffer.from(obj.fid, "base64") : obj.fid;
    f2m._transports = obj.t ? obj.t : 15;
    f2m.ckey = obj.ckey.data ? Buffer.from(obj.ckey.data) : Buffer.from(obj.ckey);
    f2m.signer = getSignerFromCkey(f2m.ckey);
    f2m.authType = getAuthTypeFromCkey(f2m.ckey);
    f2m.cypher = {
      publicKey: obj.cypher.publicKey.data ? Buffer.from(obj.cypher.publicKey.data) : Buffer.from(obj.cypher.publicKey),
    };
    return f2m;
  }

  static fromId(id: Buffer) {
    const data = decode(id) as ExportFIDO2Data;
    const f2m = new Fido2Manager();
    f2m.version = data.v ?? 0;
    f2m.capability = "public";
    f2m.fid = typeof data.f === "string" ? Buffer.from(data.f, "base64") : data.f;
    f2m.ckey = data.c;
    f2m.signer = getSignerFromCkey(data.c);
    f2m.authType = getAuthTypeFromCkey(f2m.ckey);
    f2m.cypher = {
      publicKey: data.e,
    };
    return f2m;
  }

  async getSigner() {
    return {
      sign: async (data: Buffer) => {
        if (!navigator.credentials) return null;
        // ugly request userinteraction (needed for Safari and iOS)
        try {
          await window?.CredentialUserInteractionRequest();
        } catch (error) {}
        const challenge = hash("sha256", data);
        const publicKey: PublicKeyCredentialRequestOptions = {
          challenge,
          userVerification: "preferred",
          allowCredentials: [
            {
              type: "public-key",
              id: this.fid,
              transports: getTransports(this._transports),
            },
          ],
        };
        const { response } = (await this.webAuthn.get(publicKey)) as PublicKeyCredential;
        const publicKeyResponse = response as AuthenticatorAssertionResponse;
        const output: Fido2Signature = {
          s: Buffer.from(publicKeyResponse.signature),
          c: Buffer.from(publicKeyResponse.clientDataJSON),
          a: Buffer.from(publicKeyResponse.authenticatorData),
        };
        return Buffer.from(encode(output));
      },
    };
  }

  verify(data: Buffer, signature: Buffer | Uint8Array, userVerification: boolean = false) {
    const signatureBuffer = Buffer.from(signature);
    const decoded = decode(signatureBuffer) as Fido2Signature;
    const response = {
      signature: decoded.s,
      clientDataJSON: decoded.c,
      authenticatorData: decoded.a,
      userHandle: Buffer.from([]).buffer,
    };
    const challenge = hash("sha256", data).toString("base64");
    const extractedChallenge = SoftCredentials.extractChallenge(response.clientDataJSON);
    if (challenge !== extractedChallenge) {
      return false;
    }
    return SoftCredentials.simpleVerify(this.ckey, response, userVerification);
  }

  verifyCredentials(credentials: PublicKeyCredential, userVerification = false) {
    if (credentials.id !== this.fid.toString("base64")) {
      return false;
    }
    const response = credentials.response as AuthenticatorAssertionResponse;
    const rpIdHash = Buffer.from(response.authenticatorData.slice(0, 32)).toString("hex");
    const myIdHash = sha256(Buffer.from(credentials.id, "base64")).toString("hex");
    if (rpIdHash !== myIdHash) {
      return false;
    }
    return SoftCredentials.simpleVerify(this.ckey, response, userVerification);
  }

  async createRevocationCertificate() {
    // TODO use an external id
    return null;
  }
}
