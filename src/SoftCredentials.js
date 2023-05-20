// TODO: to revamp and optimize
import crypto from "crypto";
import { randomBytes, hash as myhash, fromBase64, fromUTF8 } from "./crypto.js";
import cbor from "cbor";
import { ed25519 } from "@noble/curves/ed25519";
import { p256 } from "@noble/curves/p256";
import { p384 } from "@noble/curves/p384";
import { p521 } from "@noble/curves/p521";
import { BasicConstraintsExtension, X509Certificate } from "@peculiar/x509";

const credentials = {};

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

const hash = (alg, message) => myhash(alg.replace("-", ""), message);

const base64ToPem = (b64cert) => {
  let pemcert = "";
  for (let i = 0; i < b64cert.length; i += 64)
    pemcert += b64cert.slice(i, i + 64) + "\n";
  return (
    "-----BEGIN CERTIFICATE-----\n" + pemcert + "-----END CERTIFICATE-----"
  );
};

const getCertificateInfo = (certificate) => {
  const x509 = new X509Certificate(certificate);

  const subjectString = x509.subject;
  const issuer = x509.issuer;
  const issuerName = x509.issuerName.toString();
  const subjectParts = subjectString.split(",");

  const subject = {};
  for (const field of subjectParts) {
    const kv = field.split("=");
    subject[kv[0].trim()] = kv[1];
  }
  // console.log(subject);
  const version = x509.toTextObject().Data.Version;
  const bc = x509.getExtension(BasicConstraintsExtension);
  const basicConstraintsCA = bc ? bc.ca : false;
  return {
    issuer,
    issuerName,
    subject,
    version,
    basicConstraintsCA,
  };
};

const parseAuthData = (buffer) => {
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

const verifyPackedAttestation = async (response, userVerification = false) => {
  const attestationBuffer = Buffer.from(response.attestationObject, "base64");
  const attestationStruct = cbor.decodeAllSync(attestationBuffer)[0];
  if (attestationStruct.fmt == "none") return false;
  const authDataStruct = parseAuthData(attestationStruct.authData);

  // check if user has actually touched the device
  if (!authDataStruct.flags.up) return false;
  // check if did enter PIN code
  if (userVerification && !authDataStruct.flags.uv) return false;

  const clientDataHashBuf = hash(
    "sha256",
    Buffer.from(response.clientDataJSON, "base64url"),
  );
  const dataBuffer = Buffer.concat([
    attestationStruct.authData,
    clientDataHashBuf,
  ]);
  const signature = attestationStruct.attStmt.sig;

  let signatureIsValid = false;

  /* ----- Verify FULL attestation ----- */
  if (attestationStruct.attStmt.x5c) {
    const leafCert = base64ToPem(
      attestationStruct.attStmt.x5c[0].toString("base64"),
    );
    const certInfo = getCertificateInfo(attestationStruct.attStmt.x5c[0]);

    // console.log(certInfo);
    if (certInfo.subject.OU !== "Authenticator Attestation")
      throw new Error(
        'Batch certificate OU MUST be set strictly to "Authenticator Attestation"!',
      );

    if (!certInfo.subject.CN)
      throw new Error("Batch certificate CN MUST no be empty!");

    if (!certInfo.subject.O)
      throw new Error("Batch certificate CN MUST no be empty!");

    if (!certInfo.subject.C || certInfo.subject.C.length !== 2)
      throw new Error(
        "Batch certificate C MUST be set to two character ISO 3166 code!",
      );

    if (certInfo.basicConstraintsCA)
      throw new Error("Batch certificate basic constraints CA MUST be false!");

    if (certInfo.version !== "v3 (2)")
      throw new Error("Batch certificate version MUST be 3(ASN1 2)!");

    signatureIsValid = crypto
      .createVerify("sha256")
      .update(dataBuffer)
      .verify(leafCert, signature);
    /* ----- Verify FULL attestation ENDS ----- */
  } else if (attestationStruct.attStmt.ecdaaKeyId) {
    throw new Error("ECDAA IS NOT SUPPORTED!");
  } else {
    /* ----- Verify SURROGATE attestation ----- */
    const pubKeyCose = cbor.decodeAllSync(authDataStruct.COSEPublicKey)[0];
    const hashAlg = COSEALGHASH[pubKeyCose.get(COSEKEYS.alg)];
    const data = hash(hashAlg, dataBuffer);
    if (pubKeyCose.get(COSEKEYS.kty) === COSEKTY.EC2) {
      // ECDSA
      const x = pubKeyCose.get(COSEKEYS.x);
      const y = pubKeyCose.get(COSEKEYS.y);
      const pubKey = Buffer.concat([Buffer.from([0x04]), x, y]);
      const ec = COSECRV[pubKeyCose.get(COSEKEYS.crv)];
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

class PublicKeyCredential {
  constructor(creds) {
    this.type = "public-key";
    this.clientExtensionResults = {};
    const keys = ["id", "rawId", "response"];
    keys.forEach((key) => (this[key] = creds[key]));
  }

  getClientExtensionResults() {
    return {};
  }
}

const verifyECDSA = (data, publicKey, signature) => {
  return p256.verify(p256.Signature.fromDER(signature), data, publicKey);
};

const verifyEdDSA = (data, publicKey, signature) => {
  return ed25519.verify(signature, data, publicKey);
};

// not available in browser
const sign = (data, privateKey) => {
  return crypto.sign(null, data, privateKey);
};

// Webauthn Partial Implementation for testing
export default class SoftCredentials {
  constructor() {
    this.signCount = 0;
    this.rawId = randomBytes(32);
    this.aaguid = Buffer.alloc(16);
  }

  // credentials request payload
  static createRequest(alg, onlyStrings = false) {
    const challenge = randomBytes(32);
    if (onlyStrings) {
      challenge = Buffer.from(challenge).toString("base64");
    }
    return {
      publicKey: {
        challenge,
        rp: {
          name: "Vaultys ID",
          id: "Vaultys ID",
        },
        user: {
          id: "Vaultys Wallet ID",
          name: "Vaultys Wallet ID",
          displayName: "Vaultys Wallet ID",
        },
        pubKeyCredParams: [
          {
            type: "public-key",
            alg,
          },
        ],
      },
    };
  }

  static getCertificateInfo(response) {
    const attestationBuffer = Buffer.from(response.attestationObject, "base64");
    const attestationStruct = cbor.decodeAllSync(attestationBuffer)[0];
    if (attestationStruct.attStmt.x5c) {
      return getCertificateInfo(attestationStruct.attStmt.x5c[0]);
    } else {
      return null;
    }
  }

  static async create(data, origin = "test") {
    const options = data.publicKey;
    const credential = new SoftCredentials();
    credential.options = options;
    credential.rpId = options.rp.id;
    credential.userHandle = Buffer.from(options.user.id, "utf-8");
    credentials[credential.rawId.toString("base64")] = credential; // erase previous instance
    if (options.pubKeyCredParams[0].alg === -8) {
      credential.keyPair = await crypto.generateKeyPairSync("ed25519");
      credential.coseKey = new Map();
      credential.coseKey.set(1, 1);
      credential.coseKey.set(3, -8);
      credential.coseKey.set(-1, 6);
      const x = credential.keyPair.publicKey
        .export({ format: "der", type: "spki" })
        .slice(12);
      credential.coseKey.set(-2, x);
    } else if (options.pubKeyCredParams[0].alg === -7) {
      credential.keyPair = await crypto.generateKeyPairSync("ec", {
        namedCurve: "prime256v1",
      });
      credential.coseKey = new Map();
      credential.coseKey.set(1, 2);
      credential.coseKey.set(3, -7);
      credential.coseKey.set(-1, 6);
      const der = credential.keyPair.publicKey.export({
        format: "der",
        type: "spki",
      });
      const x = der.slice(27, 27 + 32);
      const y = der.slice(27 + 32);
      // NOT possible for nodejs < 15.9
      // const jwk = credential.keyPair.publicKey.export({format:'jwk', type:'spki'})
      //  x = Buffer.from(jwk.x, 'base64')
      //  y = Buffer.from(jwk.y, 'base64')
      credential.coseKey.set(-2, x);
      credential.coseKey.set(-3, y);
    }
    const clientData = {
      type: "webauthn.create",
      challenge: Buffer.from(options.challenge).toString("base64"),
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
      authData: Buffer.concat([
        rpIdHash,
        flags,
        signCount,
        credential.aaguid,
        rawIdLength,
        credential.rawId,
        coseKey,
      ]),
      fmt: "none",
      attStmt: {},
    };

    return new PublicKeyCredential({
      id: credential.rawId.toString("base64"),
      rawId: credential.rawId,
      response: {
        clientDataJSON: Buffer.from(JSON.stringify(clientData), "utf-8"),
        attestationObject: cbor.encode(attestationObject),
        getTransports: () => ["usb", "hybrid"],
      },
    });
  }

  static simpleVerify(COSEPublicKey, response, userVerification = false) {
    const ckey = cbor.decode(COSEPublicKey);
    const rpIdHash = response.authenticatorData.slice(0, 32);
    const flagsInt = response.authenticatorData[32];
    const counter = response.authenticatorData.slice(33, 37);

    const goodflags = userVerification
      ? !!(flagsInt & 0x04)
      : !!(flagsInt & 0x01);
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
      return verifyECDSA(data, pubKey, response.signature);
    }
    return false;
  }

  static getCOSEPublicKey(attestation) {
    const ato = cbor.decode(attestation.response.attestationObject);
    return parseAuthData(ato.authData).COSEPublicKey;
  }

  static verifyPackedAttestation(attestation, userVerification = false) {
    return verifyPackedAttestation(attestation, userVerification);
  }

  static verify(attestation, assertion, userVerifiation = false) {
    if (assertion.id !== attestation.id) return false;
    const hash = myhash("sha256", assertion.response.clientDataJSON);
    let data = Buffer.concat([assertion.response.authenticatorData, hash]);
    const ato = cbor.decode(attestation.response.attestationObject);
    const authData = parseAuthData(ato.authData);
    // check if user has actually touched the device
    if (!authData.flags.up) return false;
    // check if the user has entered his PIN code or used biometric sensor
    if (userVerifiation && !authData.flags.uv) return false;
    const ckey = cbor.decode(authData.COSEPublicKey);
    if (ckey.get(3) == -7) {
      data = myhash("sha256", data);
    }
    if (ckey.get(1) == 1) {
      // EdDSA
      const x = ckey.get(-2);
      return verifyEdDSA(data, x, assertion.response.signature);
    } else if (ckey.get(1) == 2) {
      // ECDSA
      const x = ckey.get(-2);
      const y = ckey.get(-3);
      const pubKey = Buffer.concat([Buffer.from("04", "hex"), x, y]);
      return verifyECDSA(data, pubKey, assertion.response.signature);
    }
  }

  static verifySafe(attestation, assertion, userVerifiation = false) {
    const parsedAttestation = {
      id: attestation.id,
      response: {
        attestationObject: fromBase64(attestation.response.attestationObject),
      },
    };
    const parsedAssertion = {
      id: assertion.id,
      response: {
        clientDataJSON: fromBase64(assertion.response.clientDataJSON),
        authenticatorData: fromBase64(assertion.response.authenticatorData),
        signature: fromBase64(assertion.response.signature),
      },
    };
    return this.verify(parsedAttestation, parsedAssertion, userVerifiation);
  }

  static extractChallenge(clientDataJSON) {
    const clientData = JSON.parse(
      Buffer.from(clientDataJSON, "base64").toString(),
    );
    const m = clientData.challenge.length % 4;
    return clientData.challenge
      .replace(/-/g, "+")
      .replace(/_/g, "/")
      .padEnd(clientData.challenge.length + (m === 0 ? 0 : 4 - m), "=");
  }

  static async get(data, origin = "test") {
    const options = data.publicKey;
    let credential = credentials[options.allowCredentials[0].id];
    if (!credential) {
      credential =
        credentials[
          Buffer.from(options.allowCredentials[0].id).toString("base64")
        ];
    }
    credential.signCount += 1;
    // prepare signature
    const clientData = {
      type: "webauthn.get",
      challenge: Buffer.from(options.challenge).toString("base64"),
      origin,
    };
    const clientDataHash = myhash(
      "sha256",
      fromUTF8(JSON.stringify(clientData)),
    );
    const rpIdHash = myhash("sha256", credential.rpId);
    const flags = Buffer.from("01", "hex");
    const signCount = Buffer.allocUnsafe(4);
    signCount.writeUInt32BE(credential.signCount);
    const authenticatorData = Buffer.concat([rpIdHash, flags, signCount]);
    let toSign = Buffer.concat([authenticatorData, clientDataHash]);
    const signature = sign(toSign, credential.keyPair.privateKey);
    //generate assertion
    return new PublicKeyCredential({
      id: credential.rawId.toString("base64"),
      rawId: credential.rawId,
      response: {
        authenticatorData,
        clientDataJSON: Buffer.from(JSON.stringify(clientData), "utf-8"),
        signature: signature,
        userHandle: credential.userHandle,
      },
    });
  }
}
