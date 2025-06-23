"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const saltpack_1 = require("@vaultys/saltpack");
const crypto_1 = require("../crypto");
const buffer_1 = require("buffer/");
const tweetnacl_1 = __importDefault(require("tweetnacl"));
const msgpack_1 = require("@msgpack/msgpack");
const ed25519_1 = require("@noble/curves/ed25519");
const CypherManager_1 = __importDefault(require("./CypherManager"));
ed25519_1.ed25519.CURVE = { ...ed25519_1.ed25519.CURVE };
// @ts-ignore hack to get compatibility with former @stricahq/bip32ed25519 lib
ed25519_1.ed25519.CURVE.adjustScalarBytes = (bytes) => {
    // Section 5: For X25519, in order to decode 32 random bytes as an integer scalar,
    // set the three least significant bits of the first byte
    bytes[0] &= 248; // 0b1111_1000
    // and the most significant bit of the last to zero,
    bytes[31] &= 63; // 0b0001_1111
    // set the second most significant bit of the last byte to 1
    bytes[31] |= 64; // 0b0100_0000
    return bytes;
};
const serializeID_v0 = (km) => {
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
    const version = buffer_1.Buffer.from([0x84, 0xa1, 0x76, 0]);
    const proof = buffer_1.Buffer.concat([buffer_1.Buffer.from([0xa1, 0x70]), encodeBinary(buffer_1.Buffer.from([]))]);
    const sign = buffer_1.Buffer.concat([buffer_1.Buffer.from([0xa1, 0x78]), encodeBinary(km.signer.publicKey)]);
    const cypher = buffer_1.Buffer.concat([buffer_1.Buffer.from([0xa1, 0x65]), encodeBinary(km.cypher.publicKey)]);
    return buffer_1.Buffer.concat([version, proof, sign, cypher]);
};
const sha512 = (data) => (0, crypto_1.hash)("sha512", data);
const sha256 = (data) => (0, crypto_1.hash)("sha256", data);
class Ed25519Manager extends CypherManager_1.default {
    constructor() {
        super();
        this.version = 1;
        this.capability = "private";
        this.authType = "Ed25519VerificationKey2020";
    }
    static async createFromEntropy(entropy) {
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
            publicKey: buffer_1.Buffer.from(ed25519_1.ed25519.getPublicKey(seed.slice(0, 32))),
            secretKey: seed.slice(0, 32),
        };
        const cypher = tweetnacl_1.default.box.keyPair.fromSecretKey(seed.slice(32, 64));
        km.cypher = {
            publicKey: buffer_1.Buffer.from(cypher.publicKey),
            secretKey: buffer_1.Buffer.from(cypher.secretKey),
        };
        return km;
    }
    static generate() {
        return Ed25519Manager.createFromEntropy((0, crypto_1.randomBytes)(32));
    }
    get id() {
        if (this.version === 0)
            return serializeID_v0(this);
        else
            return buffer_1.Buffer.from((0, msgpack_1.encode)({
                v: this.version,
                x: this.signer.publicKey,
                e: this.cypher.publicKey,
            }));
    }
    async getCypher() {
        // todo fetch secretKey here
        const cypher = this.cypher;
        return {
            hmac: (message) => (cypher.secretKey ? (0, crypto_1.hmac)("sha256", buffer_1.Buffer.from(cypher.secretKey), "VaultysID/" + message + "/end") : undefined),
            signcrypt: async (plaintext, publicKeys) => (0, saltpack_1.encryptAndArmor)(plaintext, cypher, publicKeys),
            decrypt: async (encryptedMessage, senderKey) => (0, saltpack_1.dearmorAndDecrypt)(encryptedMessage, cypher, senderKey),
            diffieHellman: async (publicKey) => buffer_1.Buffer.from(tweetnacl_1.default.scalarMult(cypher.secretKey, publicKey)),
        };
    }
    getSigner() {
        // todo fetch secretKey here
        const secretKey = this.signer.secretKey;
        const sign = (data) => Promise.resolve(buffer_1.Buffer.from(ed25519_1.ed25519.sign(data, secretKey)));
        //console.log(secretKey.toString("hex"), new bip32.PrivateKey(secretKey).toPublicKey().toBytes().toString("hex"), Buffer.from(ed25519.getPublicKey(secretKey)).toString("hex"));
        return Promise.resolve({ sign });
    }
    getSecret() {
        return buffer_1.Buffer.from((0, msgpack_1.encode)({
            v: this.version,
            x: this.signer.secretKey,
            e: this.cypher.secretKey,
        }));
    }
    static fromSecret(secret) {
        const data = (0, msgpack_1.decode)(secret);
        const km = new Ed25519Manager();
        km.version = data.v ?? 0;
        km.capability = "private";
        km.signer = {
            secretKey: data.x.slice(0, 32),
            publicKey: buffer_1.Buffer.from(ed25519_1.ed25519.getPublicKey(data.x.slice(0, 32))),
        };
        const cypher = tweetnacl_1.default.box.keyPair.fromSecretKey(data.e);
        km.cypher = {
            publicKey: buffer_1.Buffer.from(cypher.publicKey),
            secretKey: buffer_1.Buffer.from(cypher.secretKey),
        };
        return km;
    }
    static instantiate(obj) {
        const km = new Ed25519Manager();
        km.version = obj.version ?? 0;
        km.signer = {
            publicKey: obj.signer.publicKey.data ? buffer_1.Buffer.from(obj.signer.publicKey.data) : buffer_1.Buffer.from(obj.signer.publicKey),
        };
        km.cypher = {
            publicKey: obj.cypher.publicKey.data ? buffer_1.Buffer.from(obj.cypher.publicKey.data) : buffer_1.Buffer.from(obj.cypher.publicKey),
        };
        return km;
    }
    static fromId(id) {
        const data = (0, msgpack_1.decode)(id);
        const km = new Ed25519Manager();
        km.version = data.v ?? 0;
        km.capability = "public";
        km.signer = {
            publicKey: data.x,
        };
        km.cypher = {
            publicKey: data.e,
        };
        return km;
    }
    verify(data, signature, userVerificationIgnored) {
        return ed25519_1.ed25519.verify(signature, data, this.signer.publicKey);
    }
    cleanSecureData() {
        if (this.cypher?.secretKey) {
            (0, crypto_1.secureErase)(this.cypher.secretKey);
            delete this.cypher.secretKey;
        }
        if (this.signer?.secretKey) {
            (0, crypto_1.secureErase)(this.signer.secretKey);
            delete this.signer.secretKey;
        }
        if (this.entropy) {
            (0, crypto_1.secureErase)(this.entropy);
            delete this.entropy;
        }
    }
}
exports.default = Ed25519Manager;
