"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = require("../crypto");
const buffer_1 = require("buffer/");
const tweetnacl_1 = __importDefault(require("tweetnacl"));
const msgpack_1 = require("@msgpack/msgpack");
const pqCrypto_1 = require("../pqCrypto");
const CypherManager_1 = __importDefault(require("./CypherManager"));
const ed25519_js_1 = require("@noble/curves/ed25519.js");
const sha512 = (data) => (0, crypto_1.hash)("sha512", data);
class HybridManager extends CypherManager_1.default {
    constructor() {
        super();
        this.authType = "DilithiumEdDSAVerificationKey2025";
    }
    static async createFromEntropy(entropy) {
        const km = new HybridManager();
        km.entropy = entropy;
        km.capability = "private";
        km.seed = sha512(entropy);
        const signerSeed = sha512(km.seed.slice(0, 32));
        km.pqSigner = (0, pqCrypto_1.generateDilithiumKeyPair)(signerSeed.slice(0, 32));
        km.edSigner = {
            publicKey: buffer_1.Buffer.from(ed25519_js_1.ed25519.getPublicKey(signerSeed.slice(32, 64))),
            secretKey: signerSeed.slice(32, 64),
        };
        km.signer = {
            publicKey: buffer_1.Buffer.concat([km.edSigner.publicKey, km.pqSigner.publicKey]),
            secretKey: buffer_1.Buffer.concat([km.edSigner.secretKey, km.pqSigner.secretKey]),
        };
        const cypher = tweetnacl_1.default.box.keyPair.fromSecretKey(km.seed.slice(32, 64));
        km.cypher = {
            publicKey: buffer_1.Buffer.from(cypher.publicKey),
            secretKey: buffer_1.Buffer.from(cypher.secretKey),
        };
        return km;
    }
    static generate() {
        return HybridManager.createFromEntropy((0, crypto_1.randomBytes)(32));
    }
    getSecret() {
        return buffer_1.Buffer.from((0, msgpack_1.encode)({
            v: this.version,
            alg: "hybrid",
            s: this.seed,
        }));
    }
    get id() {
        return buffer_1.Buffer.from((0, msgpack_1.encode)({
            v: this.version,
            x: this.signer.publicKey,
            e: this.cypher.publicKey,
        }));
    }
    static fromSecret(secret) {
        const data = (0, msgpack_1.decode)(secret);
        if (data.alg !== "hybrid")
            throw new Error("Not a secret for Hybrid Cryptography");
        const km = new HybridManager();
        km.version = data.v ?? 0;
        km.capability = "private";
        km.seed = buffer_1.Buffer.from(data.s);
        const signerSeed = sha512(km.seed.slice(0, 32));
        km.pqSigner = (0, pqCrypto_1.generateDilithiumKeyPair)(signerSeed.slice(0, 32));
        km.edSigner = {
            publicKey: buffer_1.Buffer.from(ed25519_js_1.ed25519.getPublicKey(signerSeed.slice(32, 64))),
            secretKey: signerSeed.slice(32, 64),
        };
        km.signer = {
            publicKey: buffer_1.Buffer.concat([km.edSigner.publicKey, km.pqSigner.publicKey]),
            secretKey: buffer_1.Buffer.concat([km.edSigner.secretKey, km.pqSigner.secretKey]),
        };
        //km.signer = generateDilithiumKeyPair(km.seed.slice(0, 32));
        const cypher = tweetnacl_1.default.box.keyPair.fromSecretKey(km.seed.slice(32, 64));
        km.cypher = {
            publicKey: buffer_1.Buffer.from(cypher.publicKey),
            secretKey: buffer_1.Buffer.from(cypher.secretKey),
        };
        return km;
    }
    static instantiate(obj) {
        const km = new HybridManager();
        km.version = obj.version ?? 0;
        km.signer = {
            publicKey: obj.signer.publicKey.data ? buffer_1.Buffer.from(obj.signer.publicKey.data) : buffer_1.Buffer.from(obj.signer.publicKey),
        };
        km.edSigner = {
            publicKey: km.signer.publicKey.slice(0, 32),
        };
        km.pqSigner = {
            publicKey: km.signer.publicKey.slice(32),
        };
        km.cypher = {
            publicKey: obj.cypher.publicKey.data ? buffer_1.Buffer.from(obj.cypher.publicKey.data) : buffer_1.Buffer.from(obj.cypher.publicKey),
        };
        return km;
    }
    static fromId(id) {
        const data = (0, msgpack_1.decode)(id);
        const km = new HybridManager();
        km.version = data.v ?? 0;
        km.capability = "public";
        km.signer = {
            publicKey: data.x,
        };
        km.edSigner = {
            publicKey: data.x.slice(0, 32),
        };
        km.pqSigner = {
            publicKey: data.x.slice(32),
        };
        km.cypher = {
            publicKey: data.e,
        };
        // console.log(km)
        return km;
    }
    getSigner() {
        // todo fetch secretKey here
        const sign = (data) => {
            const sign1 = ed25519_js_1.ed25519.sign(data, this.edSigner.secretKey);
            const sign2 = (0, pqCrypto_1.signDilithium)(buffer_1.Buffer.concat([data, sign1]), this.pqSigner.secretKey);
            return Promise.resolve(buffer_1.Buffer.concat([sign1, sign2]));
        };
        return Promise.resolve({ sign });
    }
    verify(data, signature, userVerificationIgnored) {
        const sign1 = signature.slice(0, 64);
        const sign2 = signature.slice(64);
        const verify1 = ed25519_js_1.ed25519.verify(sign1, data, this.edSigner.publicKey);
        if (!verify1)
            return false;
        return (0, pqCrypto_1.verifyDilithium)(buffer_1.Buffer.concat([data, sign1]), sign2, this.pqSigner.publicKey);
    }
}
exports.default = HybridManager;
