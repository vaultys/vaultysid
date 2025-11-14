"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.pinEncryptInfo = void 0;
exports.getKeyMaterial = getKeyMaterial;
exports.getKey = getKey;
exports.decrypt = decrypt;
exports.encrypt = encrypt;
const abstract_1 = require("./abstract");
const buffer_1 = require("buffer/");
// PIN-specific config with higher iterations for enhanced security
exports.pinEncryptInfo = {
    ALG: "PBKDF2",
    ITERATIONS: 100000, // Less iterations for PIN as it's used more frequently
    DERIVED_KEY_TYPE: "AES-GCM",
    DERIVED_KEY_LENGTH: 256,
    HASH: "SHA-256",
    SALT_LENGTH: 16,
    IV_LENGTH: 12,
};
/**
 * Imports key material from a string
 */
function getKeyMaterial(mnemonic) {
    const enc = new TextEncoder();
    return window.crypto.subtle.importKey("raw", enc.encode(mnemonic), abstract_1.encryptInfo.ALG, false, ["deriveBits", "deriveKey"]);
}
/**
 * Derives a key from key material and salt
 */
function getKey(keyMaterial, salt) {
    return window.crypto.subtle.deriveKey({
        name: abstract_1.encryptInfo.ALG,
        salt: salt,
        iterations: abstract_1.encryptInfo.ITERATIONS,
        hash: abstract_1.encryptInfo.HASH,
    }, keyMaterial, { name: abstract_1.encryptInfo.DERIVED_KEY_TYPE, length: abstract_1.encryptInfo.DERIVED_KEY_LENGTH }, true, ["encrypt", "decrypt"]);
}
/**
 * Decrypts data using a passphrase
 */
async function decrypt(backup, passphrase) {
    if (!backup.encryptInfo)
        return backup.data;
    try {
        const keyMaterial = await getKeyMaterial(passphrase);
        const key = await getKey(keyMaterial, buffer_1.Buffer.from(backup.encryptInfo.salt, "base64"));
        const decrypted = await window.crypto.subtle.decrypt({
            name: backup.encryptInfo.DERIVED_KEY_TYPE,
            iv: buffer_1.Buffer.from(backup.encryptInfo.iv, "base64"),
        }, key, backup.data);
        return buffer_1.Buffer.from(decrypted);
    }
    catch (error) {
        console.error(error);
        return null;
    }
}
/**
 * Encrypts data using a passphrase
 */
async function encrypt(mnemonic, plaintext) {
    if (!mnemonic)
        return;
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const keyMaterial = await getKeyMaterial(mnemonic);
    const key = await window.crypto.subtle.deriveKey({
        name: abstract_1.encryptInfo.ALG,
        salt,
        iterations: abstract_1.encryptInfo.ITERATIONS,
        hash: abstract_1.encryptInfo.HASH,
    }, keyMaterial, { name: abstract_1.encryptInfo.DERIVED_KEY_TYPE, length: abstract_1.encryptInfo.DERIVED_KEY_LENGTH }, true, ["encrypt", "decrypt"]);
    const data = await window.crypto.subtle.encrypt({ name: abstract_1.encryptInfo.DERIVED_KEY_TYPE, iv }, key, plaintext);
    const backup = {
        version: 1,
        encryptInfo: { ...abstract_1.encryptInfo, iv: buffer_1.Buffer.from(iv).toString("base64"), salt: buffer_1.Buffer.from(salt).toString("base64") },
        data: buffer_1.Buffer.from(data),
    };
    return backup;
}
