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
const sha512 = (data) => (0, crypto_1.hash)("sha512", data);
const sha256 = (data) => (0, crypto_1.hash)("sha256", data);
class PQManager extends CypherManager_1.default {
    constructor() {
        super();
        this.authType = "DilithiumVerificationKey2025";
    }
    static async createFromEntropy(entropy, swapIndex = 0) {
        const km = new PQManager();
        km.entropy = entropy;
        km.capability = "private";
        km.seed = sha512(entropy);
        km.signer = (0, pqCrypto_1.generateDilithiumKeyPair)(km.seed.slice(0, 32));
        const cypher = tweetnacl_1.default.box.keyPair.fromSecretKey(km.seed.slice(32, 64));
        km.cypher = {
            publicKey: buffer_1.Buffer.from(cypher.publicKey),
            secretKey: buffer_1.Buffer.from(cypher.secretKey),
        };
        return km;
    }
    static generate() {
        return PQManager.createFromEntropy((0, crypto_1.randomBytes)(32));
    }
    getSecret() {
        return buffer_1.Buffer.from((0, msgpack_1.encode)({
            v: this.version,
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
        const km = new PQManager();
        km.version = data.v ?? 0;
        km.capability = "private";
        km.seed = buffer_1.Buffer.from(data.s);
        km.signer = (0, pqCrypto_1.generateDilithiumKeyPair)(km.seed.slice(0, 32));
        const seed2 = km.seed.slice(32, 64);
        const cypher = tweetnacl_1.default.box.keyPair.fromSecretKey(seed2);
        km.cypher = {
            publicKey: buffer_1.Buffer.from(cypher.publicKey),
            secretKey: buffer_1.Buffer.from(cypher.secretKey),
        };
        return km;
    }
    static instantiate(obj) {
        const km = new PQManager();
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
        const km = new PQManager();
        km.version = data.v ?? 0;
        km.capability = "public";
        km.signer = {
            publicKey: data.x,
        };
        km.cypher = {
            publicKey: data.e,
        };
        // console.log(km)
        return km;
    }
    getSigner() {
        // todo fetch secretKey here
        const secretKey = this.signer.secretKey;
        const sign = (data) => Promise.resolve((0, pqCrypto_1.signDilithium)(data, this.signer.secretKey));
        return Promise.resolve({ sign });
    }
    verify(data, signature, userVerificationIgnored) {
        return (0, pqCrypto_1.verifyDilithium)(data, signature, this.signer.publicKey);
    }
}
exports.default = PQManager;
