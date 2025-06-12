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
const ml_dsa_js_1 = require("@noble/post-quantum/ml-dsa.js");
const buffer_1 = require("buffer/");
const crypto_1 = require("./crypto");
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
    if (!seed)
        seed = (0, crypto_1.randomBytes)(32);
    const keyPair = ml_dsa_js_1.ml_dsa65.keygen(seed);
    return {
        publicKey: buffer_1.Buffer.from(keyPair.publicKey),
        secretKey: buffer_1.Buffer.from(keyPair.secretKey),
    };
}
/**
 * Sign a message using DILITHIUM Level 2
 * @param message - The message to sign
 * @param privateKey - The DILITHIUM private key
 * @returns Promise resolving to signature as Uint8Array
 */
function signDilithium(message, secretKey) {
    return buffer_1.Buffer.from(ml_dsa_js_1.ml_dsa65.sign(secretKey, message));
}
/**
 * Verify a DILITHIUM Level 2 signature
 * @param message - The original message
 * @param signature - The signature to verify
 * @param publicKey - The DILITHIUM public key
 * @returns Promise resolving to boolean indicating if signature is valid
 */
function verifyDilithium(message, signature, publicKey) {
    return ml_dsa_js_1.ml_dsa65.verify(publicKey, message, signature);
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
        publicKeySize: 1952, // Size in bytes for DILITHIUM2 public key
        secretKeySize: 4032, // Size in bytes for DILITHIUM2 private key
        signatureSize: 3309, // Size in bytes for DILITHIUM2 signature
    };
}
