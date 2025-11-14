/**
 * Post-Quantum Cryptography Operations
 *
 * This file contains implementations for post-quantum cryptographic algorithms
 * starting with DILITHIUM for digital signatures.
 */
import { Buffer } from "buffer/";
/**
 * COSE algorithm identifiers for post-quantum algorithms
 * Note: These values are provisional and may need to be updated as standards evolve
 */
export declare const PQ_COSE_ALG: {
    DILITHIUM2: number;
    DILITHIUM3: number;
    DILITHIUM5: number;
};
/**
 * COSE key type for DILITHIUM
 */
export declare const PQ_COSE_KEY_TYPE: {
    DILITHIUM: number;
};
/**
 * COSE key parameter identifiers for DILITHIUM
 */
export declare const PQ_COSE_KEY_PARAMS: {
    DILITHIUM_MODE: number;
    DILITHIUM_PK: number;
    DILITHIUM_SK: number;
};
/**
 * Generate a DILITHIUM Level 2 key pair
 * @returns Promise resolving to an object containing the key pair
 */
export declare function generateDilithiumKeyPair(seed?: Buffer): {
    publicKey: Buffer;
    secretKey: Buffer;
};
/**
 * Sign a message using DILITHIUM Level 2
 * @param message - The message to sign
 * @param privateKey - The DILITHIUM private key
 * @returns Promise resolving to signature as Uint8Array
 */
export declare function signDilithium(message: Uint8Array | Buffer, secretKey: Uint8Array | Buffer): Buffer;
/**
 * Verify a DILITHIUM Level 2 signature
 * @param message - The original message
 * @param signature - The signature to verify
 * @param publicKey - The DILITHIUM public key
 * @returns Promise resolving to boolean indicating if signature is valid
 */
export declare function verifyDilithium(message: Uint8Array | Buffer, signature: Uint8Array | Buffer, publicKey: Uint8Array | Buffer): boolean;
/**
 * Create a COSE key representation for a DILITHIUM public key
 * @param publicKey - The DILITHIUM public key
 * @returns Map representing the COSE key
 */
export declare function createDilithiumCoseKey(publicKey: Uint8Array | Buffer): Map<number, any>;
/**
 * Get key size information for DILITHIUM
 * @returns Object with key size information
 */
export declare function getDilithiumKeyInfo(): {
    publicKeySize: number;
    secretKeySize: number;
    signatureSize: number;
};
