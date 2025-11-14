"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.DHIES = void 0;
exports.getCypherPublicKeyFromId = getCypherPublicKeyFromId;
const saltpack_1 = require("@vaultys/saltpack");
const crypto_1 = require("../crypto");
const buffer_1 = require("buffer/");
const tweetnacl_1 = __importDefault(require("tweetnacl"));
const AbstractKeyManager_1 = __importDefault(require("./AbstractKeyManager"));
const msgpack_1 = require("@msgpack/msgpack");
const sha256 = (data) => (0, crypto_1.hash)("sha256", data);
/**
 * DHIES (Diffie-Hellman Integrated Encryption Scheme) for KeyManager
 * Provides authenticated encryption using Diffie-Hellman key exchange
 */
class DHIES {
    constructor(keyManager) {
        this.keyManager = keyManager;
    }
    /**
     * Encrypts a message for a recipient using DHIES
     *
     * @param message The plaintext message to encrypt
     * @param recipientPublicKey The recipient's public key
     * @returns Encrypted message with ephemeral public key and authentication tag, or null if encryption fails
     */
    async encrypt(message, recipientPublicKey) {
        if (this.keyManager.capability === "public") {
            console.error("Cannot encrypt with DHIES using a public KeyManager");
            return null;
        }
        const cypher = await this.keyManager.getCypher();
        // Convert message to Buffer if it's a string
        const messageBuffer = typeof message === "string" ? buffer_1.Buffer.from(message, "utf8") : message;
        try {
            // Generate ephemeral keypair for this encryption
            const ephemeralKeypair = tweetnacl_1.default.box.keyPair();
            // Derive shared secret using ephemeral private key and recipient's public key
            const sharedSecret = buffer_1.Buffer.from(tweetnacl_1.default.scalarMult(ephemeralKeypair.secretKey, recipientPublicKey));
            // Key derivation: derive encryption and MAC keys from shared secret
            // Using sender's public key (not ephemeral) for authentication
            const kdfOutput = this.kdf(sharedSecret, this.keyManager.cypher.publicKey, recipientPublicKey);
            const encryptionKey = kdfOutput.encryptionKey;
            const macKey = kdfOutput.macKey;
            // Encrypt the message using XChaCha20-Poly1305
            const nonce = (0, crypto_1.randomBytes)(24); // 24 bytes nonce for XChaCha20-Poly1305
            const ciphertext = buffer_1.Buffer.from(tweetnacl_1.default.secretbox(messageBuffer, nonce, encryptionKey));
            // Compute MAC (Message Authentication Code)
            const dataToAuthenticate = buffer_1.Buffer.concat([this.keyManager.cypher.publicKey, nonce, ciphertext]);
            const mac = this.computeMAC(macKey, dataToAuthenticate);
            // Construct the final encrypted message: nonce + ephemeralPublicKey + ciphertext + MAC
            const encryptedMessage = buffer_1.Buffer.concat([nonce, ephemeralKeypair.publicKey, ciphertext, mac]);
            // Securely erase sensitive data
            (0, crypto_1.secureErase)(sharedSecret);
            (0, crypto_1.secureErase)(ephemeralKeypair.secretKey);
            (0, crypto_1.secureErase)(encryptionKey);
            (0, crypto_1.secureErase)(macKey);
            return encryptedMessage;
        }
        catch (error) {
            console.error("DHIES encryption failed:", error);
            return null;
        }
    }
    /**
     * Decrypts a message encrypted with DHIES
     *
     * @param encryptedMessage The complete encrypted message from the encrypt method
     * @returns Decrypted message as a Buffer, or null if decryption fails
     */
    async decrypt(encryptedMessage, senderPublicKey) {
        if (this.keyManager.capability === "public") {
            console.error("Cannot decrypt with DHIES using a public KeyManager");
            return null;
        }
        try {
            // Extract components from the encrypted message
            // Format: nonce (24 bytes) + ephemeralPublicKey (32 bytes) + ciphertext + MAC (32 bytes)
            const nonce = encryptedMessage.slice(0, 24);
            const ephemeralPublicKey = encryptedMessage.slice(24, 56);
            const mac = encryptedMessage.slice(encryptedMessage.length - 32);
            const ciphertext = encryptedMessage.slice(56, encryptedMessage.length - 32);
            const cypher = await this.keyManager.getCypher();
            // Derive shared secret using recipient's private key and ephemeral public key
            const sharedSecret = buffer_1.Buffer.from(tweetnacl_1.default.scalarMult(this.keyManager.cypher.secretKey, ephemeralPublicKey));
            // Key derivation: derive encryption and MAC keys
            const kdfOutput = this.kdf(sharedSecret, senderPublicKey, this.keyManager.cypher.publicKey);
            const encryptionKey = kdfOutput.encryptionKey;
            const macKey = kdfOutput.macKey;
            // Verify MAC
            const dataToAuthenticate = buffer_1.Buffer.concat([senderPublicKey, nonce, ciphertext]);
            const computedMac = this.computeMAC(macKey, dataToAuthenticate);
            if (!this.constantTimeEqual(mac, computedMac)) {
                //console.log(mac, computedMac);
                console.error("DHIES: MAC verification failed");
                return null;
            }
            // Decrypt the ciphertext
            const plaintext = tweetnacl_1.default.secretbox.open(ciphertext, nonce, encryptionKey);
            if (!plaintext) {
                console.error("DHIES: Decryption failed");
                return null;
            }
            const result = buffer_1.Buffer.from(plaintext);
            // Securely erase sensitive data
            (0, crypto_1.secureErase)(sharedSecret);
            (0, crypto_1.secureErase)(encryptionKey);
            (0, crypto_1.secureErase)(macKey);
            return result;
        }
        catch (error) {
            console.error("DHIES decryption failed:", error);
            return null;
        }
    }
    /**
     * Key Derivation Function: Derives encryption and MAC keys from the shared secret
     */
    kdf(sharedSecret, ephemeralPublicKey, staticPublicKey) {
        // Create a context for the KDF to ensure different keys for different uses
        const context = buffer_1.Buffer.concat([buffer_1.Buffer.from("DHIES-KDF"), ephemeralPublicKey, staticPublicKey]);
        // Derive encryption key: HKDF-like construction
        const encryptionKeyMaterial = (0, crypto_1.hash)("sha512", buffer_1.Buffer.concat([
            sharedSecret,
            context,
            buffer_1.Buffer.from([0x01]), // Domain separation byte
        ]));
        // Derive MAC key (using a different domain separation byte)
        const macKeyMaterial = (0, crypto_1.hash)("sha512", buffer_1.Buffer.concat([
            sharedSecret,
            context,
            buffer_1.Buffer.from([0x02]), // Domain separation byte
        ]));
        // Use first 32 bytes of each as the actual keys (for NaCl's secretbox)
        return {
            encryptionKey: encryptionKeyMaterial.slice(0, 32),
            macKey: macKeyMaterial.slice(0, 32),
        };
    }
    /**
     * Computes MAC for authenticated encryption
     */
    computeMAC(macKey, data) {
        return (0, crypto_1.hash)("sha256", buffer_1.Buffer.concat([macKey, data]));
    }
    /**
     * Constant-time comparison of two buffers to prevent timing attacks
     */
    constantTimeEqual(a, b) {
        if (a.length !== b.length) {
            return false;
        }
        let result = 0;
        for (let i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result === 0;
    }
}
exports.DHIES = DHIES;
function getCypherPublicKeyFromId(id) {
    const data = (0, msgpack_1.decode)(id);
    return data.e;
}
class CypherManager extends AbstractKeyManager_1.default {
    constructor() {
        super();
        this.version = 1;
        this.capability = "private";
        this.authType = "";
        this.encType = "X25519KeyAgreementKey2019";
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
    cleanSecureData() {
        if (this.cypher?.secretKey) {
            (0, crypto_1.secureErase)(this.cypher.secretKey);
            delete this.cypher.secretKey;
        }
        if (this.entropy) {
            (0, crypto_1.secureErase)(this.entropy);
            delete this.entropy;
        }
    }
    /**
     * Performs a Diffie-Hellman key exchange with another KeyManager instance
     * @param otherKeyManager The other party's KeyManager instance
     * @returns A shared secret that can be used for symmetric encryption
     */
    async performDiffieHellman(otherKeyManager) {
        if (this.capability === "public") {
            console.error("Cannot perform DH key exchange with a public key capability");
            return null;
        }
        const cypher = await this.getCypher();
        const otherKey = otherKeyManager.cypher.publicKey;
        // Perform the scalar multiplication to derive the shared secret
        const sharedSecret = await cypher.diffieHellman(otherKey);
        // Hash the shared secret for better security (to derive a symmetric key)
        const derivedKey = sha256(sharedSecret);
        // Securely erase the shared secret from memory
        (0, crypto_1.secureErase)(sharedSecret);
        return derivedKey;
    }
    /**
     * Static method to perform a Diffie-Hellman key exchange between two KeyManager instances
     * @param keyManager1 First KeyManager instance
     * @param keyManager2 Second KeyManager instance
     * @returns A shared secret that both parties can derive
     */
    static async diffieHellman(keyManager1, keyManager2) {
        return keyManager1.performDiffieHellman(keyManager2);
    }
    /**
     * Encrypt a message using DHIES for a recipient
     * @param message Message to encrypt
     * @param recipientId Recipient's KeyManager ID
     * @returns Encrypted message or null if encryption fails
     */
    async dhiesEncrypt(message, recipientId) {
        const dhies = new DHIES(this);
        return dhies.encrypt(message, getCypherPublicKeyFromId(recipientId));
    }
    /**
     * Decrypt a message encrypted with DHIES
     * @param encryptedMessage Encrypted message from dhiesEncrypt
     * @returns Decrypted message or null if decryption fails
     */
    async dhiesDecrypt(encryptedMessage, senderId) {
        const dhies = new DHIES(this);
        return dhies.decrypt(encryptedMessage, getCypherPublicKeyFromId(senderId));
    }
    static async encrypt(plaintext, recipientIds) {
        const publicKeys = recipientIds.map(getCypherPublicKeyFromId);
        return await (0, saltpack_1.encryptAndArmor)(plaintext, null, publicKeys);
    }
    async signcrypt(plaintext, recipientIds) {
        const publicKeys = recipientIds.map(getCypherPublicKeyFromId);
        const cypher = await this.getCypher();
        return await cypher.signcrypt(plaintext, publicKeys);
    }
    async decrypt(encryptedMessage, senderId = null) {
        const cypher = await this.getCypher();
        const senderKey = senderId ? getCypherPublicKeyFromId(senderId) : null;
        const message = await cypher.decrypt(encryptedMessage, senderKey);
        return message.toString();
    }
    // use better hash to prevent attack
    getSecretHash(data) {
        const toHash = buffer_1.Buffer.concat([data, buffer_1.Buffer.from("secrethash"), this.cypher.secretKey]);
        return (0, crypto_1.hash)("sha256", toHash);
    }
}
exports.default = CypherManager;
