"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const saltpack_1 = require("@vaultys/saltpack");
const crypto_1 = require("./crypto");
const buffer_1 = require("buffer/");
const tweetnacl_1 = __importDefault(require("tweetnacl"));
const msgpack_1 = require("@msgpack/msgpack");
const crypto_2 = require("crypto");
const pqCrypto_1 = require("./pqCrypto");
const KeyManager_1 = __importDefault(require("./KeyManager"));
const LEVEL_ROOT = 1;
const LEVEL_DERIVED = 2;
const sha512 = (data) => (0, crypto_1.hash)("sha512", data);
const sha256 = (data) => (0, crypto_1.hash)("sha256", data);
class PQManager extends KeyManager_1.default {
    constructor() {
        super();
        this.authType = "DilithiumVerificationKey2025";
    }
    static async create_PQ_fromEntropy(entropy, swapIndex = 0) {
        const km = new PQManager();
        km.entropy = entropy;
        km.level = LEVEL_ROOT;
        km.capability = "private";
        km.seed = sha512(entropy);
        km.swapIndex = swapIndex;
        km.proof = (0, crypto_1.hash)("sha256", buffer_1.Buffer.from([]));
        km.signer = (0, pqCrypto_1.generateDilithiumKeyPair)(km.seed.slice(0, 32));
        const seed2 = sha256(km.seed.slice(32, 64));
        const cypher = tweetnacl_1.default.box.keyPair.fromSecretKey(seed2);
        km.cypher = {
            publicKey: buffer_1.Buffer.from(cypher.publicKey),
            secretKey: buffer_1.Buffer.from(cypher.secretKey),
        };
        return km;
    }
    static generate_PQ() {
        return PQManager.create_PQ_fromEntropy((0, crypto_1.randomBytes)(32));
    }
    async getCypher() {
        // todo fetch secretKey here
        const cypher = this.cypher;
        return {
            hmac: (message) => cypher.secretKey
                ? buffer_1.Buffer.from((0, crypto_2.createHmac)("sha256", buffer_1.Buffer.from(cypher.secretKey).toString("hex"))
                    .update("VaultysID/" + message + "/end")
                    .digest())
                : undefined,
            signcrypt: async (plaintext, publicKeys) => (0, saltpack_1.encryptAndArmor)(plaintext, cypher, publicKeys),
            decrypt: async (encryptedMessage, senderKey) => (0, saltpack_1.dearmorAndDecrypt)(encryptedMessage, cypher, senderKey),
            diffieHellman: async (publicKey) => buffer_1.Buffer.from(tweetnacl_1.default.scalarMult(cypher.secretKey, publicKey)),
        };
    }
    getSecret() {
        return buffer_1.Buffer.from((0, msgpack_1.encode)({
            v: this.version,
            p: this.proof,
            s: this.seed,
        }));
    }
    static fromSecret(secret) {
        const data = (0, msgpack_1.decode)(secret);
        const km = new PQManager();
        km.version = data.v ?? 0;
        km.level = LEVEL_DERIVED;
        km.capability = "private";
        km.proof = data.p;
        km.seed = buffer_1.Buffer.from(data.s);
        km.signer = (0, pqCrypto_1.generateDilithiumKeyPair)(km.seed.slice(0, 32));
        const seed2 = sha256(km.seed.slice(32, 64));
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
        km.level = obj.level;
        km.proof = obj.proof.data ? buffer_1.Buffer.from(obj.proof.data) : buffer_1.Buffer.from(obj.proof);
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
        km.level = LEVEL_DERIVED;
        km.capability = "public";
        km.proof = data.p;
        km.signer = {
            publicKey: data.x,
        };
        km.cypher = {
            publicKey: data.e,
        };
        // console.log(km)
        return km;
    }
    async sign(data) {
        if (this.capability == "public")
            return null;
        return (0, pqCrypto_1.signDilithium)(data, this.signer.secretKey);
    }
    verify(data, signature, userVerificationIgnored) {
        return (0, pqCrypto_1.verifyDilithium)(data, signature, this.signer.publicKey);
    }
}
exports.default = PQManager;
