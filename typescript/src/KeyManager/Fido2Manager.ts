import { hash, randomBytes } from "../crypto";
import cbor from "cbor";
import nacl from "tweetnacl";
import { getWebAuthnProvider, WebAuthnProvider } from "../platform/webauthn";
import { KeyPair } from ".";
import { decode, encode } from "@msgpack/msgpack";
import SoftCredentials from "../platform/SoftCredentials";
import { Buffer } from "buffer/";
import { PQ_COSE_ALG, PQ_COSE_KEY_PARAMS } from "../pqCrypto";
import CypherManager from "./CypherManager";
import { decodeRecord, readVersion, requireBytes } from "./validation";

const sha512 = (data: Buffer) => hash("sha512", data);
const sha256 = (data: Buffer) => hash("sha256", data);

declare global {
  interface Window {
    CredentialUserInteractionRequest: () => Promise<void>;
  }
}

type Fido2Signature = {
  s: Buffer;
  c: Buffer;
  a: Buffer;
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

// Bitwise `&`: `num && lookup[i]` was truthy for every transport as soon as num
// was non-zero, so allowCredentials always listed all of them and browsers
// offered a phone, a security key and the platform for any credential.
const getTransports = (num: number) => Object.keys(lookup).filter((i) => num & lookup[i as LookupType]) as AuthenticatorTransport[];
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
  else if (k.get(3) == PQ_COSE_ALG.DILITHIUM5) publicKey = k.get(PQ_COSE_KEY_PARAMS.DILITHIUM_PK);
  if (!(publicKey instanceof Uint8Array) || publicKey.length === 0) throw new Error("Unsupported or malformed FIDO2 COSE key");
  return { publicKey: Buffer.from(publicKey) } as KeyPair;
};

const serializeID_v0 = (km: Fido2Manager) => {
  const version = Buffer.from([0x83, 0xa1, 0x76, 0]);
  const ckey = Buffer.concat([Buffer.from([0xa1, 0x63, 0xc5, 0x00, km.ckey.length]), km.ckey]);
  const cypher = Buffer.concat([Buffer.from([0xa1, 0x65, 0xc5, 0x00, km.cypher.publicKey.length]), km.cypher.publicKey]);
  return Buffer.concat([version, ckey, cypher]);
};

export default class Fido2Manager extends CypherManager {
  fid!: Buffer;
  _transports: number = 0;
  ckey!: Buffer;
  private _webAuthn?: WebAuthnProvider;

  constructor() {
    super();
    this.encType = "X25519KeyAgreementKey2019";
  }

  // resolved lazily: parsing a public FIDO2 id must not require (nor silently
  // fall back to) a WebAuthn authenticator
  get webAuthn(): WebAuthnProvider {
    if (!this._webAuthn) this._webAuthn = getWebAuthnProvider();
    return this._webAuthn;
  }

  set webAuthn(provider: WebAuthnProvider) {
    this._webAuthn = provider;
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
    if (this.version === 0) return serializeID_v0(this);
    else {
      return Buffer.from(
        encode({
          v: this.version,
          c: this.ckey,
          e: this.cypher.publicKey,
        }),
      );
    }
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
    const data = decodeRecord(secret, "FIDO2 secret");
    const f2m = new Fido2Manager();
    f2m.version = readVersion(data.v);
    f2m.capability = "private";
    f2m.fid = typeof data.f === "string" ? Buffer.from(data.f, "base64") : requireBytes(data.f, "FIDO2 credential id");
    f2m._transports = typeof data.t === "number" && data.t ? data.t : 15;
    f2m.ckey = requireBytes(data.c, "FIDO2 COSE key");
    f2m.authType = getAuthTypeFromCkey(f2m.ckey);
    f2m.signer = getSignerFromCkey(f2m.ckey);
    const cypher = nacl.box.keyPair.fromSecretKey(requireBytes(data.e, "X25519 secret key", 32));
    f2m.cypher = {
      publicKey: Buffer.from(cypher.publicKey),
      secretKey: Buffer.from(cypher.secretKey),
    };

    return f2m;
  }

  static instantiate(obj: any) {
    const f2m = new this();
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
    const data = decodeRecord(id, "FIDO2 id");
    const f2m = new this();
    f2m.version = readVersion(data.v);
    f2m.capability = "public";
    if (data.f !== undefined) f2m.fid = typeof data.f === "string" ? Buffer.from(data.f, "base64") : requireBytes(data.f, "FIDO2 credential id");
    f2m.ckey = requireBytes(data.c, "FIDO2 COSE key");
    f2m.signer = getSignerFromCkey(f2m.ckey);
    f2m.authType = getAuthTypeFromCkey(f2m.ckey);
    f2m.cypher = {
      publicKey: requireBytes(data.e, "X25519 public key", 32),
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
        const transports = getTransports(this._transports);
        // A credential reachable over USB/NFC/BLE only lives on a security key:
        // hint it so the browser opens the security key prompt instead of
        // offering a phone or its password manager first.
        const onSecurityKeyOnly = transports.length > 0 && !transports.some((t) => t === "hybrid" || t === "internal");
        const publicKey: PublicKeyCredentialRequestOptions & { hints?: string[] } = {
          challenge,
          // "required", not "preferred": Challenger verifies every signature
          // with userVerification = true, so an assertion without the UV flag
          // is always rejected. With "preferred" an authenticator may skip UV —
          // Google Password Manager on a desktop with no biometric sensor does —
          // and the handshake then failed with nothing to tell why.
          userVerification: "required",
          allowCredentials: [
            {
              type: "public-key",
              id: this.fid,
              transports,
            },
          ],
        };
        if (onSecurityKeyOnly) publicKey.hints = ["security-key"];
        const { response } = (await this.webAuthn.get(publicKey)) as PublicKeyCredential;
        const publicKeyResponse = response as AuthenticatorAssertionResponse;
        // Must be Buffers, not the raw ArrayBuffers WebAuthn returns: msgpack encodes
        // a bare ArrayBuffer as an empty map instead of a bin, which silently
        // destroys the signature payload.
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
    try {
      const decoded = decodeRecord(Buffer.from(signature), "FIDO2 signature");
      const response = {
        signature: requireBytes(decoded.s, "FIDO2 signature"),
        clientDataJSON: requireBytes(decoded.c, "FIDO2 clientDataJSON"),
        authenticatorData: requireBytes(decoded.a, "FIDO2 authenticatorData"),
        userHandle: Buffer.from([]).buffer,
      };
      const challenge = hash("sha256", data).toString("base64");
      const extractedChallenge = SoftCredentials.extractChallenge(response.clientDataJSON);
      if (challenge !== extractedChallenge) {
        return false;
      }
      // simpleVerify enforces clientData.type === "webauthn.get", UP (and UV when
      // requested) and the configured rpId / origin, if any
      return SoftCredentials.simpleVerify(this.ckey, response, userVerification);
    } catch {
      return false;
    }
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
