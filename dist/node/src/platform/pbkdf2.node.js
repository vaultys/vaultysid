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
Object.defineProperty(exports, "__esModule", { value: true });
exports.getKeyMaterial = getKeyMaterial;
exports.getKey = getKey;
exports.decrypt = decrypt;
exports.encrypt = encrypt;
const crypto = __importStar(require("crypto"));
const abstract_1 = require("./abstract");
const buffer_1 = require("buffer/");
const crypto_1 = require("../crypto");
// Node-compatible version of key material import
function getKeyMaterial(mnemonic) {
    const key = buffer_1.Buffer.from(mnemonic, "utf-8");
    return Promise.resolve(crypto.createSecretKey(key));
}
// Node-compatible version of key derivation
function getKey(keyMaterial, salt) {
    return new Promise((resolve) => {
        const derivedKey = crypto.pbkdf2Sync(keyMaterial.export(), salt, abstract_1.encryptInfo.ITERATIONS, abstract_1.encryptInfo.DERIVED_KEY_LENGTH / 8, abstract_1.encryptInfo.HASH.replace("-", "").toLowerCase());
        resolve(buffer_1.Buffer.from(derivedKey));
    });
}
/**
 * Node-compatible decrypt function
 */
async function decrypt(backup, passphrase) {
    if (!backup.encryptInfo)
        return backup.data;
    try {
        const keyMaterial = await getKeyMaterial(passphrase);
        const salt = buffer_1.Buffer.from(backup.encryptInfo.salt, "base64");
        const iv = buffer_1.Buffer.from(backup.encryptInfo.iv, "base64");
        const key = await getKey(keyMaterial, salt);
        const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
        // In AES-GCM the tag is the last 16 bytes of the data
        const tagLength = 16;
        const ciphertext = backup.data.subarray(0, backup.data.length - tagLength);
        const tag = backup.data.subarray(backup.data.length - tagLength);
        decipher.setAuthTag(tag);
        const decrypted = buffer_1.Buffer.concat([decipher.update(ciphertext), decipher.final()]);
        return decrypted;
    }
    catch (error) {
        console.error("Decryption error:", error);
        return null;
    }
}
/**
 * Node-compatible encrypt function
 */
async function encrypt(mnemonic, plaintext) {
    if (!mnemonic)
        return;
    const salt = (0, crypto_1.randomBytes)(16);
    const iv = (0, crypto_1.randomBytes)(12);
    const keyMaterial = await getKeyMaterial(mnemonic);
    const key = await getKey(keyMaterial, salt);
    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
    const encrypted = buffer_1.Buffer.concat([cipher.update(plaintext), cipher.final()]);
    // Get the auth tag and append it to the ciphertext
    const tag = cipher.getAuthTag();
    const fullEncrypted = buffer_1.Buffer.concat([encrypted, tag]);
    const backup = {
        version: 1,
        encryptInfo: {
            ...abstract_1.encryptInfo,
            iv: iv.toString("base64"),
            salt: salt.toString("base64"),
        },
        data: fullEncrypted,
    };
    return backup;
}
