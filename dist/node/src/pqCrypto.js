"use strict";
/**
 * Post-Quantum Cryptography Operations
 *
 * This file contains implementations for post-quantum cryptographic algorithms
 * starting with DILITHIUM for digital signatures.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.PQ_COSE_KEY_PARAMS = exports.PQ_COSE_KEY_TYPE = exports.PQ_COSE_ALG = void 0;
exports.generateDilithiumKeyPair = generateDilithiumKeyPair;
exports.signDilithium = signDilithium;
exports.verifyDilithium = verifyDilithium;
exports.createDilithiumCoseKey = createDilithiumCoseKey;
exports.getDilithiumKeyInfo = getDilithiumKeyInfo;
const dilithium_1 = require("@asanrom/dilithium");
const buffer_1 = require("buffer/");
/**
 * COSE algorithm identifiers for post-quantum algorithms
 * Note: These values are provisional and may need to be updated as standards evolve
 */
exports.PQ_COSE_ALG = {
    // DILITHIUM variants (using negative values as per COSE convention for new algorithms)
    DILITHIUM2: -46, // Level 2 (128-bit security)
    DILITHIUM3: -47, // Level 3 (192-bit security)
    DILITHIUM5: -48, // Level 5 (256-bit security)
};
/**
 * COSE key type for DILITHIUM
 */
exports.PQ_COSE_KEY_TYPE = {
    DILITHIUM: 4, // Custom key type for DILITHIUM
};
/**
 * COSE key parameter identifiers for DILITHIUM
 */
exports.PQ_COSE_KEY_PARAMS = {
    DILITHIUM_MODE: -100, // Mode parameter (2, 3, or 5)
    DILITHIUM_PK: -101, // Public key
    DILITHIUM_SK: -102, // Secret key
};
/**
 * Generate a DILITHIUM Level 2 key pair
 * @returns Promise resolving to an object containing the key pair
 */
function generateDilithiumKeyPair(seed) {
    const level = dilithium_1.DilithiumLevel.get(2); // Get the security level config (2, 3, or 5)
    // Generate a key pair
    const keyPair = dilithium_1.DilithiumKeyPair.generate(level, seed);
    return {
        publicKey: buffer_1.Buffer.from(keyPair.getPublicKey().toBase64(), "base64"),
        secretKey: buffer_1.Buffer.from(keyPair.getPrivateKey().toBase64(), "base64"),
    };
}
/**
 * Sign a message using DILITHIUM Level 2
 * @param message - The message to sign
 * @param privateKey - The DILITHIUM private key
 * @returns Promise resolving to signature as Uint8Array
 */
function signDilithium(message, secretKey) {
    const DKey = dilithium_1.DilithiumPrivateKey.fromBytes(secretKey, dilithium_1.DilithiumLevel.get(2));
    return buffer_1.Buffer.from(DKey.sign(message).getBytes());
}
/**
 * Verify a DILITHIUM Level 2 signature
 * @param message - The original message
 * @param signature - The signature to verify
 * @param publicKey - The DILITHIUM public key
 * @returns Promise resolving to boolean indicating if signature is valid
 */
function verifyDilithium(message, signature, publicKey) {
    // Ensure we're working with Uint8Array
    const DKey = dilithium_1.DilithiumPublicKey.fromBytes(publicKey, dilithium_1.DilithiumLevel.get(2));
    try {
        return DKey.verifySignature(message, dilithium_1.DilithiumSignature.fromBytes(signature, dilithium_1.DilithiumLevel.get(2)));
    }
    catch (error) {
        console.error("DILITHIUM verification error:", error);
        return false;
    }
}
/**
 * Create a COSE key representation for a DILITHIUM public key
 * @param publicKey - The DILITHIUM public key
 * @returns Map representing the COSE key
 */
function createDilithiumCoseKey(publicKey) {
    const coseKey = new Map();
    // Standard COSE key parameters
    coseKey.set(1, exports.PQ_COSE_KEY_TYPE.DILITHIUM); // kty: Key Type
    coseKey.set(3, exports.PQ_COSE_ALG.DILITHIUM2); // alg: Algorithm
    // DILITHIUM-specific parameters
    coseKey.set(exports.PQ_COSE_KEY_PARAMS.DILITHIUM_MODE, 2); // Level 2
    coseKey.set(exports.PQ_COSE_KEY_PARAMS.DILITHIUM_PK, publicKey);
    return coseKey;
}
/**
 * Get key size information for DILITHIUM
 * @returns Object with key size information
 */
function getDilithiumKeyInfo() {
    return {
        publicKeySize: 1312, // Size in bytes for DILITHIUM2 public key
        secretKeySize: 2544, // Size in bytes for DILITHIUM2 private key
        signatureSize: 2420, // Size in bytes for DILITHIUM2 signature
    };
}
