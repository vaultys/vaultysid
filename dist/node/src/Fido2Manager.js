"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = require("./crypto");
const cbor_1 = __importDefault(require("cbor"));
const tweetnacl_1 = __importDefault(require("tweetnacl"));
const webauthn_1 = require("./platform/webauthn");
const KeyManager_1 = __importDefault(require("./KeyManager"));
const msgpack_1 = require("@msgpack/msgpack");
const SoftCredentials_1 = __importDefault(require("./platform/SoftCredentials"));
const buffer_1 = require("buffer/");
const pqCrypto_1 = require("./pqCrypto");
const sha512 = (data) => (0, crypto_1.hash)("sha512", data);
const sha256 = (data) => (0, crypto_1.hash)("sha256", data);
const lookup = {
    usb: 1,
    nfc: 2,
    ble: 4,
    internal: 8,
    hybrid: 16,
    "smart-card": 32,
};
const encodeBinary = (data) => {
    if (data.length <= 65535) {
        // bin16: binary data whose length is upto (2^16)-1 bytes
        return buffer_1.Buffer.from([0xc5, data.length >> 8, data.length & 0xff, ...data]);
    }
    else {
        // bin32: binary data whose length is upto (2^32)-1 bytes
        return buffer_1.Buffer.from([0xc6, (data.length >> 24) & 0xff, (data.length >> 16) & 0xff, (data.length >> 8) & 0xff, data.length & 0xff, ...data]);
    }
};
const serializeID_v0 = (km) => {
    const version = buffer_1.Buffer.from([0x83, 0xa1, 0x76, km.version]);
    const cypher = buffer_1.Buffer.concat([buffer_1.Buffer.from([0xa1, 0x65]), encodeBinary(km.cypher.publicKey)]);
    const ckey = buffer_1.Buffer.concat([buffer_1.Buffer.from([0xa1, 0x63]), encodeBinary(km.ckey)]);
    return buffer_1.Buffer.concat([version, ckey, cypher]);
};
const getTransports = (num) => Object.keys(lookup).filter((i) => num && lookup[i]);
const fromTransports = (transports) => transports.reduceRight((memo, i) => memo + (lookup[i] ? lookup[i] : 0), 0);
const getAuthTypeFromCkey = (ckey) => {
    const type = cbor_1.default.decode(ckey).get(1);
    if (type === 1) {
        return "Ed25519VerificationKey2020";
    }
    else if (type === 2) {
        return "P256VerificationKey2020";
    }
    else
        return "Unknown";
};
const getSignerFromCkey = (ckey) => {
    const k = cbor_1.default.decode(ckey);
    let publicKey = buffer_1.Buffer.from([]);
    if (k.get(3) == -7)
        publicKey = buffer_1.Buffer.concat([buffer_1.Buffer.from("04", "hex"), k.get(-2), k.get(-3)]);
    else if (k.get(3) == -8)
        publicKey = k.get(-2);
    else if (k.get(3) == pqCrypto_1.PQ_COSE_ALG.DILITHIUM2)
        publicKey = k.get(-101);
    return { publicKey };
};
class Fido2Manager extends KeyManager_1.default {
    constructor() {
        super();
        this._transports = 0;
        this.level = 1; // ROOT, no Proof Management
        this.encType = "X25519KeyAgreementKey2019";
        this.webAuthn = (0, webauthn_1.getWebAuthnProvider)();
    }
    get transports() {
        return getTransports(this._transports);
    }
    static async createFromAttestation(attestation) {
        const f2m = new Fido2Manager();
        f2m.ckey = SoftCredentials_1.default.getCOSEPublicKey(attestation);
        f2m.authType = getAuthTypeFromCkey(f2m.ckey);
        f2m.fid = buffer_1.Buffer.from(attestation.id, "base64");
        // fix for firefox, getTransports not available ! https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAttestationResponse/getTransports
        const response = attestation.response;
        const transports = response.getTransports ? response.getTransports() : ["usb"];
        f2m._transports = fromTransports(transports);
        // signing
        f2m.signer = getSignerFromCkey(f2m.ckey);
        //encrypting
        const entropy = (0, crypto_1.randomBytes)(32);
        const seed = sha512(entropy);
        const cypher = tweetnacl_1.default.box.keyPair.fromSecretKey(seed.slice(0, 32));
        f2m.cypher = {
            publicKey: buffer_1.Buffer.from(cypher.publicKey),
            secretKey: buffer_1.Buffer.from(cypher.secretKey),
        };
        f2m.entropy = entropy;
        return f2m;
    }
    get id() {
        if (this.version == 0)
            return serializeID_v0(this);
        else
            return buffer_1.Buffer.from((0, msgpack_1.encode)({
                v: this.version,
                c: this.ckey,
                e: this.cypher.publicKey,
            }));
    }
    get id_v0() {
        return serializeID_v0(this);
    }
    getSecret() {
        return buffer_1.Buffer.from((0, msgpack_1.encode)({
            v: this.version,
            f: this.fid,
            t: this._transports,
            c: this.ckey,
            e: this.cypher.secretKey,
        }));
    }
    static fromSecret(secret) {
        const data = (0, msgpack_1.decode)(secret);
        const f2m = new Fido2Manager();
        f2m.version = data.v ?? 0;
        f2m.capability = "private";
        f2m.fid = typeof data.f === "string" ? buffer_1.Buffer.from(data.f, "base64") : data.f;
        f2m._transports = data.t ? data.t : 15;
        f2m.ckey = data.c;
        f2m.authType = getAuthTypeFromCkey(f2m.ckey);
        f2m.signer = getSignerFromCkey(data.c);
        const cypher = tweetnacl_1.default.box.keyPair.fromSecretKey(data.e);
        f2m.cypher = {
            publicKey: buffer_1.Buffer.from(cypher.publicKey),
            secretKey: buffer_1.Buffer.from(cypher.secretKey),
        };
        return f2m;
    }
    static instantiate(obj) {
        const f2m = new Fido2Manager();
        f2m.version = obj.version ?? 0;
        f2m.level = obj.level;
        f2m.fid = typeof obj.fid === "string" ? buffer_1.Buffer.from(obj.fid, "base64") : obj.fid;
        f2m._transports = obj.t ? obj.t : 15;
        f2m.ckey = obj.ckey.data ? buffer_1.Buffer.from(obj.ckey.data) : buffer_1.Buffer.from(obj.ckey);
        f2m.signer = getSignerFromCkey(f2m.ckey);
        f2m.authType = getAuthTypeFromCkey(f2m.ckey);
        f2m.cypher = {
            publicKey: obj.cypher.publicKey.data ? buffer_1.Buffer.from(obj.cypher.publicKey.data) : buffer_1.Buffer.from(obj.cypher.publicKey),
        };
        return f2m;
    }
    static fromId(id) {
        const data = (0, msgpack_1.decode)(id);
        const f2m = new Fido2Manager();
        f2m.version = data.v ?? 0;
        f2m.capability = "public";
        f2m.fid = typeof data.f === "string" ? buffer_1.Buffer.from(data.f, "base64") : data.f;
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
            sign: async (data) => {
                if (!navigator.credentials)
                    return null;
                // ugly request userinteraction (needed for Safari and iOS)
                try {
                    await window?.CredentialUserInteractionRequest();
                }
                catch (error) { }
                const challenge = (0, crypto_1.hash)("sha256", data);
                const publicKey = {
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
                const { response } = (await this.webAuthn.get(publicKey));
                const publicKeyResponse = response;
                const output = {
                    s: buffer_1.Buffer.from(publicKeyResponse.signature),
                    c: buffer_1.Buffer.from(publicKeyResponse.clientDataJSON),
                    a: buffer_1.Buffer.from(publicKeyResponse.authenticatorData),
                };
                return buffer_1.Buffer.from((0, msgpack_1.encode)(output));
            },
        };
    }
    verify(data, signature, userVerification = false) {
        const signatureBuffer = buffer_1.Buffer.from(signature);
        const decoded = (0, msgpack_1.decode)(signatureBuffer);
        const response = {
            signature: decoded.s,
            clientDataJSON: decoded.c,
            authenticatorData: decoded.a,
            userHandle: buffer_1.Buffer.from([]).buffer,
        };
        const challenge = (0, crypto_1.hash)("sha256", data).toString("base64");
        const extractedChallenge = SoftCredentials_1.default.extractChallenge(response.clientDataJSON);
        if (challenge !== extractedChallenge) {
            return false;
        }
        return SoftCredentials_1.default.simpleVerify(this.ckey, response, userVerification);
    }
    verifyCredentials(credentials, userVerification = false) {
        if (credentials.id !== this.fid.toString("base64")) {
            return false;
        }
        const response = credentials.response;
        const rpIdHash = buffer_1.Buffer.from(response.authenticatorData.slice(0, 32)).toString("hex");
        const myIdHash = sha256(buffer_1.Buffer.from(credentials.id, "base64")).toString("hex");
        if (rpIdHash !== myIdHash) {
            return false;
        }
        return SoftCredentials_1.default.simpleVerify(this.ckey, response, userVerification);
    }
    async createRevocationCertificate() {
        // TODO use an external id
        return null;
    }
}
exports.default = Fido2Manager;
