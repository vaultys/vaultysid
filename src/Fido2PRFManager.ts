import { secureErase } from "./crypto";
import cbor from "cbor";
import nacl from "tweetnacl";
import SoftCredentials from "./platform/SoftCredentials";
import { KeyPair } from "./KeyManager";
import { decode, encode } from "@msgpack/msgpack";
import Fido2Manager from "./Fido2Manager";
import { Buffer } from "buffer/";

declare global {
  interface Window {
    CredentialUserInteractionRequest: () => Promise<void>;
  }
}

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

const getTransports = (num: number) => Object.keys(lookup).filter((i) => num && lookup[i as LookupType]);
const fromTransports = (transports: string[]): number => transports.reduceRight((memo, i) => memo + (lookup[i as LookupType] ? lookup[i as LookupType] : 0), 0);

const getAuthTypeFromCkey = (ckey: Buffer) => {
  const decoded = cbor.decode(ckey, { extendedResults: true });
  const type = decoded.value.get(1);
  if (type === 1) {
    return "Ed25519VerificationKey2020";
  } else if (type === 2) {
    return "P256VerificationKey2020";
  } else return "Unknown";
};

const getSignerFromCkey = (ckey: Buffer) => {
  const k = cbor.decode(ckey, { extendedResults: true }).value;
  let publicKey: Buffer = Buffer.from([]);
  if (k.get(3) == -7) publicKey = Buffer.concat([Buffer.from("04", "hex"), k.get(-2), k.get(-3)]);
  else if (k.get(3) == -8) publicKey = k.get(-2);
  return { publicKey } as KeyPair;
};

export default class Fido2PRFManager extends Fido2Manager {
  prfsalt = Buffer.from("VaultysID salt");

  constructor() {
    super();
  }

  static async createFromAttestation(attestation: PublicKeyCredential) {
    const f2m = new Fido2PRFManager();
    f2m.ckey = SoftCredentials.getCOSEPublicKey(attestation)!;
    //console.log(attestation, f2m.ckey);
    f2m.authType = getAuthTypeFromCkey(f2m.ckey);
    f2m.fid = Buffer.from(attestation.id, "base64");

    // fix for firefox, getTransports not available ! https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAttestationResponse/getTransports
    const response = attestation.response as AuthenticatorAttestationResponse;
    const transports = response.getTransports ? response.getTransports() : ["usb"];
    f2m._transports = fromTransports(transports);

    // signing
    f2m.signer = getSignerFromCkey(f2m.ckey);
    await f2m.getCypher();
    delete f2m.cypher.secretKey;
    return f2m;
  }

  getSecret() {
    return Buffer.from(
      encode({
        v: this.version,
        f: this.fid,
        t: this._transports,
        c: this.ckey,
        e: this.cypher.publicKey,
      }),
    );
  }

  static fromSecret(secret: Buffer) {
    const data = decode(secret) as ExportFIDO2Data;
    const f2m = new Fido2PRFManager();
    f2m.version = data.v ?? 0;
    f2m.capability = "private";
    f2m.fid = typeof data.f === "string" ? Buffer.from(data.f, "base64") : data.f;
    f2m._transports = data.t ? data.t : 15;
    f2m.ckey = data.c;
    f2m.authType = getAuthTypeFromCkey(f2m.ckey);
    f2m.signer = getSignerFromCkey(data.c);
    f2m.cypher = { publicKey: data.e };
    return f2m;
  }

  cleanSecureData() {
    if (this.cypher?.secretKey) {
      secureErase(this.cypher.secretKey);
      delete this.cypher.secretKey;
    }
  }

  async getCypher() {
    if (!this.cypher?.secretKey) {
      const publicKey: PublicKeyCredentialRequestOptions = {
        challenge: Buffer.from([]),
        userVerification: "preferred",
        allowCredentials: [
          {
            type: "public-key",
            id: this.fid,
            transports: getTransports(this._transports) as AuthenticatorTransport[],
          },
        ],
        extensions: {
          prf: {
            eval: {
              // Input the contextual information
              first: this.prfsalt,
              // There is a "second" optional field too
              // Though it is intended for key rotation.
            },
          },
        },
      };
      const result = await this.webAuthn.get(publicKey);
      const { prf } = result.getClientExtensionResults();
      const first = prf?.results?.first;
      if (!first) throw new Error("PRF failed");
      const cypher = nacl.box.keyPair.fromSecretKey(new Uint8Array(first as any));
      this.cypher = {
        publicKey: Buffer.from(cypher.publicKey),
        secretKey: Buffer.from(cypher.secretKey),
      };
    }

    return super.getCypher();
  }

  async createRevocationCertificate() {
    // impossible
    return null;
  }
}
