// TODO: to revamp and optimize
import crypto from "crypto";
import { randomBytes, hash as myhash, fromUTF8 } from "./crypto";
import cbor from "cbor";
import { ed25519 } from "@noble/curves/ed25519";
import { p256 } from "@noble/curves/p256";
import { p384 } from "@noble/curves/p384";
import { p521 } from "@noble/curves/p521";
import { BasicConstraintsExtension, X509Certificate } from "@peculiar/x509";

const credentials: Record<string, SoftCredentials> = {};

//const subtle = crypto.webcrypto ? crypto.webcrypto.subtle : crypto.subtle;

const COSEKEYS = {
  kty: 1,
  alg: 3,
  crv: -1,
  x: -2,
  y: -3,
  n: -1,
  e: -2,
};

const COSEKTY = {
  OKP: 1,
  EC2: 2,
  RSA: 3,
};

const COSERSASCHEME = {
  "-3": "pss-sha256",
  "-39": "pss-sha512",
  "-38": "pss-sha384",
  "-65535": "pkcs1-sha1",
  "-257": "pkcs1-sha256",
  "-258": "pkcs1-sha384",
  "-259": "pkcs1-sha512",
};

const COSECRV = {
  1: p256,
  2: p384,
  3: p521,
};

type HashOptions = "-257" | "-258" | "-259" | "-65535" | "-39" | "-38" | "-37" | "-260" | "-261" | "-7" | "-36";

const COSEALGHASH = {
  "-257": "SHA-256",
  "-258": "SHA-384",
  "-259": "SHA-512",
  "-65535": "SHA-1",
  "-39": "SHA-512",
  "-38": "SHA-384",
  "-37": "SHA-256",
  "-260": "SHA-256",
  "-261": "SHA-512",
  "-7": "SHA-256",
  "-36": "SHA-512",
};

const hash = (alg: string, message: Buffer) => myhash(alg.replace("-", ""), message);

const base64ToPem = (b64cert: string) => {
  let pemcert = "";
  for (let i = 0; i < b64cert.length; i += 64) pemcert += b64cert.slice(i, i + 64) + "\n";
  return "-----BEGIN CERTIFICATE-----\n" + pemcert + "-----END CERTIFICATE-----";
};

const getCertificateInfo = (certificate: Buffer) => {
  const x509 = new X509Certificate(certificate);

  const subjectString = x509.subject;
  const issuer = x509.issuer;
  const issuerName = x509.issuerName.toString();
  const subjectParts = subjectString.split(",");

  const subject: Record<string, string> = {};
  for (const field of subjectParts) {
    const kv = field.split("=");
    subject[kv[0].trim()] = kv[1];
  }
  // console.log(subject);
  const { Version } = x509.toTextObject().Data as unknown as { Version: string };
  const bc = x509.getExtension(BasicConstraintsExtension);
  const basicConstraintsCA = bc ? bc.ca : false;
  return {
    issuer,
    issuerName,
    subject,
    version: Version,
    basicConstraintsCA,
  };
};

const parseAuthData = (buffer: Buffer) => {
  const rpIdHash = buffer.slice(0, 32);
  buffer = buffer.slice(32);
  const flagsBuf = buffer.slice(0, 1);
  buffer = buffer.slice(1);
  const flagsInt = flagsBuf[0];
  const flags = {
    up: !!(flagsInt & 0x01),
    uv: !!(flagsInt & 0x04),
    at: !!(flagsInt & 0x40),
    ed: !!(flagsInt & 0x80),
    flagsInt,
  };

  const counterBuf = buffer.slice(0, 4);
  buffer = buffer.slice(4);
  const counter = counterBuf.readUInt32BE(0);

  let aaguid = undefined;
  let credID = undefined;
  let COSEPublicKey = undefined;

  if (flags.at) {
    aaguid = buffer.slice(0, 16);
    buffer = buffer.slice(16);
    const credIDLenBuf = buffer.slice(0, 2);
    buffer = buffer.slice(2);
    const credIDLen = credIDLenBuf.readUInt16BE(0);
    credID = buffer.slice(0, credIDLen);
    buffer = buffer.slice(credIDLen);
    COSEPublicKey = buffer;
  }
  //console.log(aaguid);

  return {
    rpIdHash,
    flagsBuf,
    flags,
    counter,
    counterBuf,
    aaguid,
    credID,
    COSEPublicKey,
  };
};

const verifyPackedAttestation = async (response: AuthenticatorAttestationResponse, userVerification = false) => {
  const attestationBuffer = Buffer.from(response.attestationObject);
  const attestationStruct = cbor.decodeAllSync(attestationBuffer)[0];
  if (attestationStruct.fmt == "none") return false;
  const authDataStruct = parseAuthData(attestationStruct.authData);

  // check if user has actually touched the device
  if (!authDataStruct.flags.up) return false;
  // check if did enter PIN code
  if (userVerification && !authDataStruct.flags.uv) return false;

  const clientDataHashBuf = hash("sha256", Buffer.from(response.clientDataJSON));
  const dataBuffer = Buffer.concat([attestationStruct.authData, clientDataHashBuf]);
  const signature = attestationStruct.attStmt.sig;

  let signatureIsValid = false;

  /* ----- Verify FULL attestation ----- */
  if (attestationStruct.attStmt.x5c) {
    const leafCert = base64ToPem(attestationStruct.attStmt.x5c[0].toString("base64"));
    const certInfo = getCertificateInfo(attestationStruct.attStmt.x5c[0]);
    const subject = certInfo.subject as {
      OU: string;
      O: string;
      C: string;
      CN: string;
    };

    // console.log(certInfo);
    if (subject.OU !== "Authenticator Attestation") throw new Error('Batch certificate OU MUST be set strictly to "Authenticator Attestation"!');

    if (!subject.CN) throw new Error("Batch certificate CN MUST no be empty!");

    if (!subject.O) throw new Error("Batch certificate O MUST no be empty!");

    if (!subject.C || subject.C.length !== 2) throw new Error("Batch certificate C MUST be set to two character ISO 3166 code!");

    if (certInfo.basicConstraintsCA) throw new Error("Batch certificate basic constraints CA MUST be false!");

    if (certInfo.version !== "v3 (2)") throw new Error("Batch certificate version MUST be 3(ASN1 2)!");

    signatureIsValid = crypto.createVerify("sha256").update(dataBuffer).verify(leafCert, signature);
    /* ----- Verify FULL attestation ENDS ----- */
  } else if (attestationStruct.attStmt.ecdaaKeyId) {
    throw new Error("ECDAA IS NOT SUPPORTED!");
  } else {
    /* ----- Verify SURROGATE attestation ----- */
    const pubKeyCose = cbor.decodeAllSync(authDataStruct.COSEPublicKey!)[0];
    const hashAlg = COSEALGHASH[pubKeyCose.get(COSEKEYS.alg) as HashOptions];
    const data = hash(hashAlg, dataBuffer);
    if (pubKeyCose.get(COSEKEYS.kty) === COSEKTY.EC2) {
      // ECDSA
      const x = pubKeyCose.get(COSEKEYS.x);
      const y = pubKeyCose.get(COSEKEYS.y);
      const pubKey = Buffer.concat([Buffer.from([0x04]), x, y]);
      const ec = COSECRV[pubKeyCose.get(COSEKEYS.crv) as 1 | 2 | 3];
      const sig = ec.Signature.fromDER(signature);
      signatureIsValid = ec.verify(sig, data, pubKey);
    } else if (pubKeyCose.get(COSEKEYS.kty) === COSEKTY.OKP) {
      // EdDSA
      const x = pubKeyCose.get(COSEKEYS.x);
      signatureIsValid = ed25519.verify(signature, data, x);
    } else {
      return false;
    }
    /* ----- Verify SURROGATE attestation ENDS ----- */
  }

  if (!signatureIsValid) throw new Error("Failed to verify the signature!");
  return true;
};

class MyPublicKeyCredential {
  type: "public-key";
  clientExtensionResults: any;
  id!: string;
  rawId!: Buffer;
  response!: AuthenticatorAttestationResponse;
  constructor(creds: PublicKeyCredential) {
    this.type = "public-key";
    this.clientExtensionResults = {};
    const keys = ["id", "rawId", "response"];
    this.id = creds.id;
    this.rawId = Buffer.from(creds.rawId);
    this.response = creds.response as AuthenticatorAttestationResponse;
  }

  getClientExtensionResults() {
    return {};
  }
}

const verifyECDSA = (data: Buffer, publicKey: Buffer, signature: Buffer) => {
  return p256.verify(p256.Signature.fromDER(signature).toCompactHex(), data, publicKey);
};

const verifyEdDSA = (data: Buffer, publicKey: Buffer, signature: Buffer) => {
  return ed25519.verify(signature, data, publicKey);
};

type SoftKeyPair = {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
};
// Webauthn Partial Implementation for testing
export default class SoftCredentials {
  signCount: number;
  rawId: Buffer;
  aaguid: Buffer;
  challenge!: Buffer;
  options!: PublicKeyCredentialCreationOptions;
  rpId!: string;
  userHandle!: Buffer;
  alg!: number;
  keyPair!: SoftKeyPair;
  coseKey!: Map<number, number | Uint8Array>;

  constructor() {
    this.signCount = 0;
    this.rawId = randomBytes(32);
    this.aaguid = Buffer.alloc(16);
  }

  // credentials request payload
  static createRequest(alg: number, prf = false) {
    const challenge = Buffer.from(randomBytes(32).toString("base64"));

    const result: CredentialCreationOptions = {
      publicKey: {
        challenge,
        rp: {
          name: "Vaultys ID",
          id: "Vaultys ID",
        },
        user: {
          id: Buffer.from("Vaultys Wallet ID", "utf8"),
          name: "Vaultys Wallet ID",
          displayName: "Vaultys Wallet ID",
        },
        pubKeyCredParams: [
          {
            type: "public-key" as const,
            alg,
          },
        ],
      },
    };

    if (prf) {
      result.publicKey!.extensions = { prf: { eval: { first: randomBytes(32) } } };
    }

    return result;
  }

  static getCertificateInfo(response: AuthenticatorAttestationResponse) {
    const attestationBuffer = Buffer.from(response.attestationObject);
    const attestationStruct = cbor.decodeAllSync(attestationBuffer)[0];
    if (attestationStruct.attStmt.x5c) {
      return getCertificateInfo(attestationStruct.attStmt.x5c[0]);
    } else {
      return null;
    }
  }

  static async create(options: CredentialCreationOptions, origin = "test"): Promise<PublicKeyCredential> {
    const credential = new SoftCredentials();
    const publicKey = options.publicKey!;
    credential.options = publicKey;
    credential.rpId = publicKey.rp.id!;
    credential.userHandle = Buffer.from(publicKey.user.id as ArrayBuffer);
    credentials[credential.rawId.toString("base64")] = credential; // erase previous instance
    credential.alg = publicKey.pubKeyCredParams[0].alg;
    if (credential.alg === -8) {
      const random = ed25519.utils.randomPrivateKey();
      credential.keyPair = {
        privateKey: random,
        publicKey: ed25519.getPublicKey(random),
      };
      credential.coseKey = new Map();
      credential.coseKey.set(1, 1);
      credential.coseKey.set(3, -8);
      credential.coseKey.set(-1, 6);
      const x = credential.keyPair.publicKey.slice(0, 32);
      credential.coseKey.set(-2, x);
    } else if (credential.alg === -7) {
      const random = p256.utils.randomPrivateKey();
      credential.keyPair = {
        privateKey: random,
        publicKey: p256.getPublicKey(random, false),
      };
      credential.coseKey = new Map();
      credential.coseKey.set(1, 2);
      credential.coseKey.set(3, -7);
      credential.coseKey.set(-1, 6);
      const x = credential.keyPair.publicKey.slice(1, 33);
      const y = credential.keyPair.publicKey.slice(33);
      credential.coseKey.set(-2, x);
      credential.coseKey.set(-3, y);
      // console.log(extpk,x,y)
    }
    const clientData = {
      type: "webauthn.create",
      challenge: publicKey.challenge,
      origin,
    };

    const rpIdHash = myhash("sha256", Buffer.from(credential.rpId, "ascii"));
    const flags = Buffer.from("41", "hex"); // attested_data + user_present
    const signCount = Buffer.allocUnsafe(4);
    signCount.writeUInt32BE(credential.signCount);
    const rawIdLength = Buffer.allocUnsafe(2);
    rawIdLength.writeUInt16BE(credential.rawId.length);
    const coseKey = cbor.encode(credential.coseKey);
    const attestationObject = {
      authData: Buffer.concat([rpIdHash, flags, signCount, credential.aaguid, rawIdLength, credential.rawId, coseKey]),
      fmt: "none",
      attStmt: {},
    };

    const pkCredentials: PublicKeyCredential = {
      id: credential.rawId.toString("base64"),
      rawId: credential.rawId,
      authenticatorAttachment: null,
      type: "public-key",
      getClientExtensionResults: () => {
        if (publicKey.extensions?.prf?.eval?.first) {
          return { prf: { enabled: true } };
        } else {
          return {};
        }
      },
      toJSON() {},
      response: {
        clientDataJSON: Buffer.from(JSON.stringify(clientData), "utf-8"),
        attestationObject: cbor.encode(attestationObject),
        getTransports: () => ["usb", "hybrid"],
        getAuthenticatorData: () => attestationObject.authData,
        getPublicKey: () => coseKey,
        getPublicKeyAlgorithm: () => -7,
      } as AuthenticatorAttestationResponse,
    };

    return pkCredentials;
  }

  static simpleVerify(COSEPublicKey: Buffer, response: AuthenticatorAssertionResponse, userVerification = false) {
    const ckey = cbor.decode(COSEPublicKey, { extendedResults: true }).value;
    const rpIdHash = response.authenticatorData.slice(0, 32);
    const flagsInt = Buffer.from(response.authenticatorData)[32];
    const counter = response.authenticatorData.slice(33, 37);

    const goodflags = userVerification ? !!(flagsInt & 0x04) : !!(flagsInt & 0x01);
    if (!goodflags) return false;

    const hash = myhash("sha256", Buffer.from(response.clientDataJSON));
    let data = Buffer.concat([Buffer.from(response.authenticatorData), hash]);
    if (ckey.get(3) == -7) {
      data = myhash("sha256", data);
    }
    if (ckey.get(1) == 1) {
      // EdDSA
      const x = ckey.get(-2);
      return verifyEdDSA(data, x, Buffer.from(response.signature));
    } else if (ckey.get(1) == 2) {
      // ECDSA
      const x = ckey.get(-2);
      const y = ckey.get(-3);
      const pubKey = Buffer.concat([Buffer.from("04", "hex"), x, y]);
      return verifyECDSA(data, pubKey, Buffer.from(response.signature));
    }
    return false;
  }

  static getCOSEPublicKey(attestation: PublicKeyCredential) {
    const response = attestation.response as AuthenticatorAttestationResponse;
    const ato = cbor.decode(response.attestationObject);
    return parseAuthData(ato.authData).COSEPublicKey;
  }

  static verifyPackedAttestation(attestation: AuthenticatorAttestationResponse, userVerification = false) {
    return verifyPackedAttestation(attestation, userVerification);
  }

  static verify(attestation: PublicKeyCredential, assertion: PublicKeyCredential, userVerifiation = false) {
    //if (assertion.id !== attestation.id) return false;
    const hash = myhash("sha256", Buffer.from(assertion.response.clientDataJSON));
    const ass = assertion.response as AuthenticatorAssertionResponse;
    const att = attestation.response as AuthenticatorAttestationResponse;
    let data = Buffer.concat([Buffer.from(ass.authenticatorData), hash]);
    const ato = cbor.decode(att.attestationObject);
    const authData = parseAuthData(ato.authData);
    // check if user has actually touched the device
    if (!authData.flags.up) return false;
    // check if the user has entered his PIN code or used biometric sensor
    if ((userVerifiation && !authData.flags.uv) || !authData.COSEPublicKey) return false;
    const ckey = cbor.decode(authData.COSEPublicKey);
    if (ckey.get(3) == -7) {
      data = myhash("sha256", data);
    }
    if (ckey.get(1) == 1) {
      // EdDSA
      const x = ckey.get(-2);
      return verifyEdDSA(data, x, Buffer.from(ass.signature));
    } else if (ckey.get(1) == 2) {
      // ECDSA
      const x = ckey.get(-2);
      const y = ckey.get(-3);
      const pubKey = Buffer.concat([Buffer.from("04", "hex"), x, y]);
      return verifyECDSA(data, pubKey, Buffer.from(ass.signature));
    }
  }

  static extractChallenge(clientDataJSON: Buffer) {
    const clientData = JSON.parse(clientDataJSON.toString());
    const m = clientData.challenge.length % 4;
    return clientData.challenge
      .replace(/-/g, "+")
      .replace(/_/g, "/")
      .padEnd(clientData.challenge.length + (m === 0 ? 0 : 4 - m), "=");
  }

  static async get({ publicKey }: { publicKey: PublicKeyCredentialRequestOptions }, origin = "test"): Promise<PublicKeyCredential> {
    if (!publicKey.allowCredentials) throw new Error();
    const id = Buffer.from(publicKey.allowCredentials[0].id as ArrayBuffer).toString("base64");
    const credential = credentials[id];
    credential.signCount += 1;
    // prepare signature
    const clientData = {
      type: "webauthn.get",
      challenge: Buffer.from(publicKey.challenge as ArrayBuffer).toString("base64"),
      origin,
    };
    const clientDataHash = myhash("sha256", fromUTF8(JSON.stringify(clientData)));
    const rpIdHash = myhash("sha256", Buffer.from(credential.rpId, "utf-8"));
    const flags = Buffer.from("05", "hex"); // user verification
    const signCount = Buffer.allocUnsafe(4);
    signCount.writeUInt32BE(credential.signCount);
    const authenticatorData = Buffer.concat([rpIdHash, flags, signCount]);
    const toSign = Buffer.concat([authenticatorData, clientDataHash]);
    let signature: Uint8Array = new Uint8Array();
    if (credential.alg === -7) {
      signature = p256.sign(toSign, credential.keyPair.privateKey, { prehash: true }).toDERRawBytes();
    } else if (credential.alg === -8) {
      signature = ed25519.sign(toSign, credential.keyPair.privateKey);
    }

    const pkCredentials: PublicKeyCredential = {
      id,
      rawId: Buffer.from(id, "base64"),
      type: "public-key",
      authenticatorAttachment: null,
      getClientExtensionResults: () => {
        if (publicKey.extensions?.prf?.eval?.first) {
          // unsafe and not following w3c recommendation. for testing purpose only
          return { prf: { results: { first: hash("sha256", publicKey.extensions?.prf?.eval?.first as Buffer) } } };
        } else {
          return {};
        }
      },
      toJSON() {},
      response: {
        authenticatorData,
        clientDataJSON: Buffer.from(JSON.stringify(clientData), "utf-8"),
        signature: signature,
        userHandle: credential.userHandle,
      } as AuthenticatorAssertionResponse,
    };

    return pkCredentials;
  }
}
