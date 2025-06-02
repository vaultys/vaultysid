"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
// TODO: to revamp and optimize
const crypto_1 = __importDefault(require("crypto"));
const buffer_1 = require("buffer/");
const crypto_2 = require("../crypto");
const cbor_1 = __importDefault(require("cbor"));
const ed25519_1 = require("@noble/curves/ed25519");
const p256_1 = require("@noble/curves/p256");
const p384_1 = require("@noble/curves/p384");
const p521_1 = require("@noble/curves/p521");
const x509_1 = require("@peculiar/x509");
const pqCrypto_1 = require("../pqCrypto");
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
    DILITHIUM: pqCrypto_1.PQ_COSE_KEY_TYPE.DILITHIUM,
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
    1: p256_1.p256,
    2: p384_1.p384,
    3: p521_1.p521,
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
    [pqCrypto_1.PQ_COSE_ALG.DILITHIUM2.toString()]: "SHA-256", // DILITHIUM2 uses SHA-256 for hashing
};
const hash = (alg, message) => (0, crypto_2.hash)(alg.replace("-", ""), message);
const base64ToPem = (b64cert) => {
    let pemcert = "";
    for (let i = 0; i < b64cert.length; i += 64)
        pemcert += b64cert.slice(i, i + 64) + "\n";
    return "-----BEGIN CERTIFICATE-----\n" + pemcert + "-----END CERTIFICATE-----";
};
const getCertificateInfo = (certificate) => {
    const x509 = new x509_1.X509Certificate(certificate);
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
    const { Version } = x509.toTextObject().Data;
    const bc = x509.getExtension(x509_1.BasicConstraintsExtension);
    const basicConstraintsCA = bc ? bc.ca : false;
    return {
        issuer,
        issuerName,
        subject,
        version: Version,
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
const verifyPackedAttestation = (response, userVerification = false) => {
    const attestationBuffer = buffer_1.Buffer.from(response.attestationObject);
    const attestationStruct = cbor_1.default.decodeAllSync(attestationBuffer)[0];
    if (attestationStruct.fmt == "none")
        return false;
    const authDataStruct = parseAuthData(attestationStruct.authData);
    // check if user has actually touched the device
    if (!authDataStruct.flags.up)
        return false;
    // check if did enter PIN code
    if (userVerification && !authDataStruct.flags.uv)
        return false;
    const clientDataHashBuf = hash("sha256", buffer_1.Buffer.from(response.clientDataJSON));
    const dataBuffer = buffer_1.Buffer.concat([attestationStruct.authData, clientDataHashBuf]);
    const signature = attestationStruct.attStmt.sig;
    let signatureIsValid = false;
    /* ----- Verify FULL attestation ----- */
    if (attestationStruct.attStmt.x5c) {
        const leafCert = base64ToPem(attestationStruct.attStmt.x5c[0].toString("base64"));
        const certInfo = getCertificateInfo(attestationStruct.attStmt.x5c[0]);
        const subject = certInfo.subject;
        // console.log(certInfo);
        if (subject.OU !== "Authenticator Attestation")
            throw new Error('Batch certificate OU MUST be set strictly to "Authenticator Attestation"!');
        if (!subject.CN)
            throw new Error("Batch certificate CN MUST no be empty!");
        if (!subject.O)
            throw new Error("Batch certificate O MUST no be empty!");
        if (!subject.C || subject.C.length !== 2)
            throw new Error("Batch certificate C MUST be set to two character ISO 3166 code!");
        if (certInfo.basicConstraintsCA)
            throw new Error("Batch certificate basic constraints CA MUST be false!");
        if (certInfo.version !== "v3 (2)")
            throw new Error("Batch certificate version MUST be 3(ASN1 2)!");
        signatureIsValid = crypto_1.default.createVerify("sha256").update(dataBuffer).verify(leafCert, signature);
        /* ----- Verify FULL attestation ENDS ----- */
    }
    else if (attestationStruct.attStmt.ecdaaKeyId) {
        throw new Error("ECDAA IS NOT SUPPORTED!");
    }
    else {
        /* ----- Verify SURROGATE attestation ----- */
        const pubKeyCose = cbor_1.default.decodeAllSync(authDataStruct.COSEPublicKey)[0];
        const hashAlg = COSEALGHASH[pubKeyCose.get(COSEKEYS.alg)];
        const data = hash(hashAlg, dataBuffer);
        if (pubKeyCose.get(COSEKEYS.kty) === COSEKTY.EC2) {
            // ECDSA
            const x = pubKeyCose.get(COSEKEYS.x);
            const y = pubKeyCose.get(COSEKEYS.y);
            const pubKey = buffer_1.Buffer.concat([buffer_1.Buffer.from([0x04]), x, y]);
            const ec = COSECRV[pubKeyCose.get(COSEKEYS.crv)];
            const sig = ec.Signature.fromDER(signature);
            signatureIsValid = ec.verify(sig, data, pubKey);
        }
        else if (pubKeyCose.get(COSEKEYS.kty) === COSEKTY.OKP) {
            // EdDSA
            const x = pubKeyCose.get(COSEKEYS.x);
            signatureIsValid = ed25519_1.ed25519.verify(signature, data, x);
        }
        else {
            return false;
        }
        /* ----- Verify SURROGATE attestation ENDS ----- */
    }
    if (!signatureIsValid)
        throw new Error("Failed to verify the signature!");
    return true;
};
class MyPublicKeyCredential {
    constructor(creds) {
        this.type = "public-key";
        this.clientExtensionResults = {};
        const keys = ["id", "rawId", "response"];
        this.id = creds.id;
        this.rawId = buffer_1.Buffer.from(creds.rawId);
        this.response = creds.response;
    }
    getClientExtensionResults() {
        return {};
    }
}
const verifyECDSA = (data, publicKey, signature) => {
    return p256_1.p256.verify(p256_1.p256.Signature.fromDER(signature).toCompactHex(), data, publicKey);
};
const verifyEdDSA = (data, publicKey, signature) => {
    return ed25519_1.ed25519.verify(signature, data, publicKey);
};
// Webauthn Partial Implementation for testing
class SoftCredentials {
    constructor() {
        this.signCount = 0;
        this.rawId = (0, crypto_2.randomBytes)(32);
        this.aaguid = buffer_1.Buffer.alloc(16);
    }
    // credentials request payload
    static createRequest(alg, prf = false) {
        const challenge = buffer_1.Buffer.from((0, crypto_2.randomBytes)(32).toString("base64"));
        const result = {
            publicKey: {
                challenge,
                rp: {
                    name: "Vaultys ID",
                    id: "Vaultys ID",
                },
                user: {
                    id: buffer_1.Buffer.from("Vaultys Wallet ID", "utf8"),
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
        if (prf) {
            result.publicKey.extensions = { prf: { eval: { first: (0, crypto_2.randomBytes)(32) } } };
        }
        return result;
    }
    static getCertificateInfo(response) {
        const attestationBuffer = buffer_1.Buffer.from(response.attestationObject);
        const attestationStruct = cbor_1.default.decodeAllSync(attestationBuffer)[0];
        if (attestationStruct.attStmt.x5c) {
            return getCertificateInfo(attestationStruct.attStmt.x5c[0]);
        }
        else {
            return null;
        }
    }
    static async create(options, origin = "test") {
        const credential = new SoftCredentials();
        const publicKey = options.publicKey;
        credential.options = publicKey;
        credential.rpId = publicKey.rp.id || publicKey.rp.name;
        credential.userHandle = buffer_1.Buffer.from(publicKey.user.id.toString(), "base64");
        credentials[credential.rawId.toString("base64")] = credential; // erase previous instance
        // Get the algorithm from pubKeyCredParams
        const pubKeyCredParams = publicKey.pubKeyCredParams;
        // Check if DILITHIUM is supported (look for PQ_COSE_ALG.DILITHIUM2 in the params)
        const supportsDilithium = pubKeyCredParams.some((param) => param.alg === pqCrypto_1.PQ_COSE_ALG.DILITHIUM2);
        // Set algorithm, prioritizing DILITHIUM if it's supported
        if (supportsDilithium) {
            credential.alg = pqCrypto_1.PQ_COSE_ALG.DILITHIUM2;
        }
        else {
            credential.alg = publicKey.pubKeyCredParams[0].alg;
        }
        if (credential.alg === -8) {
            const random = ed25519_1.ed25519.utils.randomPrivateKey();
            credential.keyPair = {
                privateKey: random,
                publicKey: ed25519_1.ed25519.getPublicKey(random),
                algorithm: "EdDSA",
            };
            credential.coseKey = new Map();
            credential.coseKey.set(1, 1);
            credential.coseKey.set(3, -8);
            credential.coseKey.set(-1, 6);
            const x = credential.keyPair.publicKey.slice(0, 32);
            credential.coseKey.set(-2, x);
        }
        else if (credential.alg === -7) {
            const random = p256_1.p256.utils.randomPrivateKey();
            credential.keyPair = {
                privateKey: random,
                publicKey: p256_1.p256.getPublicKey(random, false),
                algorithm: "ES256",
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
        else if (credential.alg === pqCrypto_1.PQ_COSE_ALG.DILITHIUM2) {
            // Generate DILITHIUM key pair
            const { publicKey: dilithiumPk, secretKey: dilithiumSk } = (0, pqCrypto_1.generateDilithiumKeyPair)();
            //console.log("PQC", dilithiumPk, dilithiumSk);
            credential.keyPair = {
                privateKey: dilithiumSk,
                publicKey: dilithiumPk,
                algorithm: "DILITHIUM2",
                isDILITHIUM: true,
            };
            // Create COSE key representation
            credential.coseKey = (0, pqCrypto_1.createDilithiumCoseKey)(dilithiumPk);
            //console.log("PQC", credential);
        }
        const clientData = {
            type: "webauthn.create",
            challenge: publicKey.challenge,
            origin,
        };
        const rpIdHash = (0, crypto_2.hash)("sha256", buffer_1.Buffer.from(credential.rpId, "ascii"));
        const flags = buffer_1.Buffer.from("41", "hex"); // attested_data + user_present
        const signCount = buffer_1.Buffer.allocUnsafe(4);
        signCount.writeUInt32BE(credential.signCount, 0);
        const rawIdLength = buffer_1.Buffer.allocUnsafe(2);
        rawIdLength.writeUInt16BE(credential.rawId.length, 0);
        const coseKey = cbor_1.default.encode(credential.coseKey);
        const attestationObject = {
            authData: buffer_1.Buffer.concat([rpIdHash, flags, signCount, credential.aaguid, rawIdLength, credential.rawId, coseKey]),
            fmt: "none",
            attStmt: {},
        };
        const pkCredentials = {
            id: credential.rawId.toString("base64"),
            rawId: credential.rawId,
            authenticatorAttachment: null,
            type: "public-key",
            getClientExtensionResults: () => {
                if (publicKey.extensions?.prf?.eval?.first) {
                    return { prf: { enabled: true } };
                }
                else {
                    return {};
                }
            },
            toJSON() { },
            response: {
                clientDataJSON: buffer_1.Buffer.from(JSON.stringify(clientData), "utf-8"),
                attestationObject: cbor_1.default.encode(attestationObject),
                getTransports: () => ["usb", "hybrid"],
                getAuthenticatorData: () => attestationObject.authData,
                getPublicKey: () => coseKey,
                getPublicKeyAlgorithm: () => -7,
            },
        };
        return pkCredentials;
    }
    static simpleVerify(COSEPublicKey, response, userVerification = false) {
        const ckey = cbor_1.default.decode(COSEPublicKey, { extendedResults: true }).value;
        const rpIdHash = response.authenticatorData.slice(0, 32);
        const flagsInt = buffer_1.Buffer.from(response.authenticatorData)[32];
        const counter = response.authenticatorData.slice(33, 37);
        const goodflags = userVerification ? !!(flagsInt & 0x04) : !!(flagsInt & 0x01);
        if (!goodflags)
            return false;
        const hash = (0, crypto_2.hash)("sha256", buffer_1.Buffer.from(response.clientDataJSON));
        let data = buffer_1.Buffer.concat([buffer_1.Buffer.from(response.authenticatorData), hash]);
        if (ckey.get(3) == -7) {
            data = (0, crypto_2.hash)("sha256", data);
        }
        if (ckey.get(1) == 1) {
            // EdDSA
            const x = ckey.get(-2);
            return verifyEdDSA(data, x, buffer_1.Buffer.from(response.signature));
        }
        else if (ckey.get(1) == 2) {
            // ECDSA
            const x = ckey.get(-2);
            const y = ckey.get(-3);
            const pubKey = buffer_1.Buffer.concat([buffer_1.Buffer.from("04", "hex"), x, y]);
            return verifyECDSA(data, pubKey, buffer_1.Buffer.from(response.signature));
        }
        else if (ckey.get(1) === COSEKTY.DILITHIUM) {
            // DILITHIUM
            const publicKey = ckey.get(pqCrypto_1.PQ_COSE_KEY_PARAMS.DILITHIUM_PK);
            // Verify DILITHIUM signature asynchronously
            //console.log(data, publicKey, Buffer.from(response.signature));
            return (0, pqCrypto_1.verifyDilithium)(data, buffer_1.Buffer.from(response.signature), publicKey);
        }
        return false;
    }
    static getCOSEPublicKey(attestation) {
        const response = attestation.response;
        const ato = cbor_1.default.decode(response.attestationObject);
        //console.log("getCOSEPublicKey", ato, parseAuthData(ato.authData));
        return parseAuthData(ato.authData).COSEPublicKey;
    }
    static verifyPackedAttestation(attestation, userVerification = false) {
        return verifyPackedAttestation(attestation, userVerification);
    }
    static async verify(attestation, assertion, userVerifiation = false) {
        //if (assertion.id !== attestation.id) return false;
        const hash = (0, crypto_2.hash)("sha256", buffer_1.Buffer.from(assertion.response.clientDataJSON));
        const ass = assertion.response;
        const att = attestation.response;
        let data = buffer_1.Buffer.concat([buffer_1.Buffer.from(ass.authenticatorData), hash]);
        const ato = cbor_1.default.decode(att.attestationObject);
        const authData = parseAuthData(ato.authData);
        // check if user has actually touched the device
        if (!authData.flags.up)
            return false;
        // check if the user has entered his PIN code or used biometric sensor
        if ((userVerifiation && !authData.flags.uv) || !authData.COSEPublicKey)
            return false;
        const ckey = cbor_1.default.decode(authData.COSEPublicKey);
        // Hash data for ES256
        if (ckey.get(3) == -7) {
            data = (0, crypto_2.hash)("sha256", data);
        }
        // Get key type
        const keyType = ckey.get(1);
        if (keyType === 1) {
            // EdDSA
            const x = ckey.get(-2);
            return verifyEdDSA(data, x, buffer_1.Buffer.from(ass.signature));
        }
        else if (keyType === 2) {
            // ECDSA
            const x = ckey.get(-2);
            const y = ckey.get(-3);
            const pubKey = buffer_1.Buffer.concat([buffer_1.Buffer.from("04", "hex"), x, y]);
            return verifyECDSA(data, pubKey, buffer_1.Buffer.from(ass.signature));
        }
        else if (keyType === COSEKTY.DILITHIUM) {
            // DILITHIUM
            const publicKey = ckey.get(pqCrypto_1.PQ_COSE_KEY_PARAMS.DILITHIUM_PK);
            // Verify DILITHIUM signature asynchronously
            //console.log(data, publicKey, Buffer.from(ass.signature));
            return (0, pqCrypto_1.verifyDilithium)(data, buffer_1.Buffer.from(ass.signature), publicKey);
        }
        return false;
    }
    static extractChallenge(clientDataJSON) {
        const clientData = JSON.parse(clientDataJSON.toString());
        const m = clientData.challenge.length % 4;
        return clientData.challenge
            .replace(/-/g, "+")
            .replace(/_/g, "/")
            .padEnd(clientData.challenge.length + (m === 0 ? 0 : 4 - m), "=");
    }
    static async get({ publicKey }, origin = "test") {
        if (!publicKey.allowCredentials)
            throw new Error();
        const id = buffer_1.Buffer.from(publicKey.allowCredentials[0].id).toString("base64");
        const credential = credentials[id];
        credential.signCount += 1;
        // prepare signature
        const clientData = {
            type: "webauthn.get",
            challenge: buffer_1.Buffer.from(publicKey.challenge).toString("base64"),
            origin,
        };
        const clientDataHash = (0, crypto_2.hash)("sha256", (0, crypto_2.fromUTF8)(JSON.stringify(clientData)));
        const rpIdHash = (0, crypto_2.hash)("sha256", buffer_1.Buffer.from(credential.rpId, "utf-8"));
        const flags = buffer_1.Buffer.from("05", "hex"); // user verification
        const signCount = buffer_1.Buffer.allocUnsafe(4);
        signCount.writeUInt32BE(credential.signCount, 0);
        const authenticatorData = buffer_1.Buffer.concat([rpIdHash, flags, signCount]);
        const toSign = buffer_1.Buffer.concat([authenticatorData, clientDataHash]);
        let signature = new Uint8Array();
        if (credential.alg === -7) {
            signature = p256_1.p256.sign(toSign, credential.keyPair.privateKey, { prehash: true }).toDERRawBytes();
        }
        else if (credential.alg === -8) {
            signature = ed25519_1.ed25519.sign(toSign, credential.keyPair.privateKey);
        }
        else if (credential.alg === pqCrypto_1.PQ_COSE_ALG.DILITHIUM2) {
            // DILITHIUM signing - this returns a Promise so we need to await it
            signature = (0, pqCrypto_1.signDilithium)(toSign, credential.keyPair.privateKey);
        }
        const pkCredentials = {
            id,
            rawId: buffer_1.Buffer.from(id, "base64").buffer,
            type: "public-key",
            authenticatorAttachment: null,
            getClientExtensionResults: () => {
                if (publicKey.extensions?.prf?.eval?.first) {
                    // unsafe and not following w3c recommendation. for testing purpose only
                    return { prf: { results: { first: hash("sha256", publicKey.extensions?.prf?.eval?.first) } } };
                }
                else {
                    return {};
                }
            },
            toJSON() { },
            response: {
                authenticatorData,
                clientDataJSON: buffer_1.Buffer.from(JSON.stringify(clientData), "utf-8"),
                signature: signature,
                userHandle: credential.userHandle,
            },
        };
        return pkCredentials;
    }
}
exports.default = SoftCredentials;
