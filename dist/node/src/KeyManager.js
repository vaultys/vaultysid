"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.privateDerivePath = exports.publicDerivePath = void 0;
const saltpack_1 = require("@samuelthomas2774/saltpack");
const crypto_1 = require("./crypto");
const buffer_1 = require("buffer/");
const tweetnacl_1 = __importDefault(require("tweetnacl"));
const msgpack_1 = require("@msgpack/msgpack");
const bip32fix = __importStar(require("@stricahq/bip32ed25519"));
const crypto_2 = require("crypto");
//@ts-expect-error fix for wrong way of exporting bip32ed25519
const bip32 = bip32fix.default ?? bip32fix;
const LEVEL_ROOT = 1;
const LEVEL_DERIVED = 2;
const sha512 = (data) => (0, crypto_1.hash)("sha512", data);
const sha256 = (data) => (0, crypto_1.hash)("sha256", data);
const serializeID_v0 = (km) => {
    const version = buffer_1.Buffer.from([0x84, 0xa1, 0x76, 0]);
    const proof = buffer_1.Buffer.from([0xa1, 0x70, 0xc5, 0x00, km.proof.length, ...km.proof]);
    const sign = buffer_1.Buffer.from([0xa1, 0x78, 0xc5, 0x00, km.signer.publicKey.length, ...km.signer.publicKey]);
    const cypher = buffer_1.Buffer.from([0xa1, 0x65, 0xc5, 0x00, km.cypher.publicKey.length, ...km.cypher.publicKey]);
    return buffer_1.Buffer.concat([version, proof, sign, cypher]);
};
const publicDerivePath = (node, path) => {
    let result = node;
    if (path.startsWith("m/"))
        path = path.slice(2);
    path.split("/").forEach((d) => {
        if (d[d.length - 1] == "'")
            result = result.derive(2147483648 + parseInt(d.substring(0, d.length - 1)));
        else
            result = result.derive(parseInt(d));
    });
    return result;
};
exports.publicDerivePath = publicDerivePath;
const privateDerivePath = (node, path) => {
    let result = node;
    if (path.startsWith("m/"))
        path = path.slice(2);
    path.split("/").forEach((d) => {
        if (d[d.length - 1] == "'")
            result = result.derive(2147483648 + parseInt(d.substring(0, d.length - 1)));
        else
            result = result.derive(parseInt(d));
    });
    return result;
};
exports.privateDerivePath = privateDerivePath;
class KeyManager {
    constructor() {
        this.level = 1;
        this.version = 1;
        this.capability = "private";
        this.authType = "Ed25519VerificationKey2020";
        this.encType = "X25519KeyAgreementKey2019";
    }
    static async create_Id25519_fromEntropy(entropy, swapIndex = 0) {
        const km = new KeyManager();
        km.entropy = entropy;
        km.level = LEVEL_ROOT;
        km.capability = "private";
        const seed = sha512(entropy);
        const derivedKey = (0, exports.privateDerivePath)(await bip32.Bip32PrivateKey.fromEntropy(seed.slice(0, 32)), `m/1'/0'/${swapIndex}'`);
        km.proofKey = {
            publicKey: derivedKey.toBip32PublicKey().toPublicKey().toBytes(),
            secretKey: derivedKey.toBytes(),
        };
        km.swapIndex = swapIndex;
        km.proof = (0, crypto_1.hash)("sha256", km.proofKey.publicKey);
        const privateKey = (0, exports.privateDerivePath)(derivedKey, "/0'");
        km.signer = {
            publicKey: privateKey.toBip32PublicKey().toPublicKey().toBytes(),
            secretKey: privateKey.toBytes(),
        };
        const swapIndexBuffer = buffer_1.Buffer.alloc(8);
        swapIndexBuffer.writeBigInt64LE(BigInt(swapIndex), 0);
        const seed2 = sha256(buffer_1.Buffer.concat([seed.slice(32, 64), swapIndexBuffer]));
        const cypher = tweetnacl_1.default.box.keyPair.fromSecretKey(seed2);
        km.cypher = {
            publicKey: buffer_1.Buffer.from(cypher.publicKey),
            secretKey: buffer_1.Buffer.from(cypher.secretKey),
        };
        return km;
    }
    static generate_Id25519() {
        return KeyManager.create_Id25519_fromEntropy((0, crypto_1.randomBytes)(32));
    }
    get id() {
        if (this.version == 0)
            return serializeID_v0(this);
        else
            return buffer_1.Buffer.from((0, msgpack_1.encode)({
                v: this.version,
                p: this.proof,
                x: this.signer.publicKey,
                e: this.cypher.publicKey,
            }));
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
        };
    }
    async getSigner() {
        // todo fetch secretKey here
        const secretKey = this.signer.secretKey;
        return new bip32.Bip32PrivateKey(secretKey).toPrivateKey();
    }
    getSecret() {
        return buffer_1.Buffer.from((0, msgpack_1.encode)({
            v: this.version,
            p: this.proof,
            x: this.signer.secretKey,
            e: this.cypher.secretKey,
        }));
    }
    static fromSecret(secret) {
        const data = (0, msgpack_1.decode)(secret);
        const km = new KeyManager();
        km.version = data.v ?? 0;
        km.level = LEVEL_DERIVED;
        km.capability = "private";
        km.proof = data.p;
        km.signer = {
            secretKey: data.x,
            publicKey: new bip32.Bip32PrivateKey(data.x).toBip32PublicKey().toPublicKey().toBytes(),
        };
        const cypher = tweetnacl_1.default.box.keyPair.fromSecretKey(data.e);
        km.cypher = {
            publicKey: buffer_1.Buffer.from(cypher.publicKey),
            secretKey: buffer_1.Buffer.from(cypher.secretKey),
        };
        return km;
    }
    static instantiate(obj) {
        const km = new KeyManager();
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
        const km = new KeyManager();
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
        const signer = await this.getSigner();
        return signer.sign(data);
    }
    verify(data, signature, userVerificationIgnored) {
        return bip32.Bip32PublicKey.fromBytes(this.signer.publicKey).toPublicKey().verify(signature, data);
    }
    // async createRevocationCertificate(newId) {
    //   if (this.level == LEVEL_ROOT) {
    //     const seed = sha512(this.entropy);
    //     let node = derivePath(
    //       await Bip32PrivateKey.fromEntropy(seed.slice(0, 32)),
    //       "m/1'/0'/1'",
    //     );
    //     const proof = hash("sha256", node.toBip32PublicKey().toBytes());
    //     if (this.proof.toString("hex") == proof.toString("hex")) {
    //       const revocationCertificate = {
    //         xpub: node.toBytes(),
    //         id: this.id,
    //         newId,
    //       };
    //       revocationCertificate.signature = node.toPrivateKey().sign(revocationCertificate);
    //       return revocationCertificate;
    //     } else return null;
    //   } else return null;
    // }
    async createSwapingCertificate() {
        if (this.level === LEVEL_ROOT && this.entropy) {
            const newKey = await KeyManager.create_Id25519_fromEntropy(this.entropy, this.swapIndex + 1);
            const hiscp = {
                newId: newKey.id,
                proofKey: this.proofKey.publicKey,
                timestamp: Date.now(),
                signature: buffer_1.Buffer.from([]),
            };
            const timestampBuffer = buffer_1.Buffer.alloc(8);
            timestampBuffer.writeBigUInt64LE(BigInt(hiscp.timestamp), 0);
            const hiscpBuffer = buffer_1.Buffer.concat([hiscp.newId, hiscp.proofKey, timestampBuffer]);
            hiscp.signature = new bip32.Bip32PrivateKey(this.proofKey.secretKey).toPrivateKey().sign(hiscpBuffer);
            return hiscp;
        }
        return null;
    }
    async verifySwapingCertificate(hiscp) {
        const proof = (0, crypto_1.hash)("sha256", hiscp.proofKey).toString("hex");
        if (proof === this.proof.toString("hex")) {
            const timestampBuffer = buffer_1.Buffer.alloc(8);
            timestampBuffer.writeBigUInt64LE(BigInt(hiscp.timestamp), 0);
            const newKey = KeyManager.fromId(hiscp.newId);
            const hiscpBuffer = buffer_1.Buffer.concat([hiscp.newId, hiscp.proofKey, timestampBuffer]);
            const proofVerifier = bip32.Bip32PublicKey.fromBytes(hiscp.proofKey);
            return proofVerifier.toPublicKey().verify(hiscpBuffer, hiscp.signature);
        }
        else {
            return false;
        }
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
    static async encrypt(plaintext, recipientIds) {
        const publicKeys = recipientIds.map(KeyManager.fromId).map((km) => km.cypher.publicKey);
        return await (0, saltpack_1.encryptAndArmor)(plaintext, null, publicKeys);
    }
    async signcrypt(plaintext, recipientIds) {
        const publicKeys = recipientIds.map(KeyManager.fromId).map((km) => km.cypher.publicKey);
        const cypher = await this.getCypher();
        return await cypher.signcrypt(plaintext, publicKeys);
    }
    async decrypt(encryptedMessage, senderId = null) {
        const cypher = await this.getCypher();
        const senderKey = senderId ? KeyManager.fromId(senderId).cypher.publicKey : null;
        const message = await cypher.decrypt(encryptedMessage, senderKey);
        return message.toString();
    }
    // use better hash to prevent attack
    getSecretHash(data) {
        const toHash = buffer_1.Buffer.concat([data, buffer_1.Buffer.from("secrethash"), this.cypher.secretKey]);
        return (0, crypto_1.hash)("sha256", toHash);
    }
}
exports.default = KeyManager;
