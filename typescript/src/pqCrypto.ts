/**
 * Post-Quantum Cryptography Operations
 *
 * This file contains implementations for post-quantum cryptographic algorithms
 * starting with DILITHIUM for digital signatures.
 */

import { ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { Buffer } from "buffer/";
import { randomBytes } from "./crypto";

/**
 * COSE algorithm identifiers for post-quantum algorithms
 * Note: These values are provisional and may need to be updated as standards evolve
 */
export const PQ_COSE_ALG = {
  // DILITHIUM variants (using negative values as per COSE convention for new algorithms)
  DILITHIUM2: -46, // Level 2 (128-bit security)
  DILITHIUM3: -47, // Level 3 (192-bit security)
  DILITHIUM5: -48, // Level 5 (256-bit security)
};

/**
 * COSE key type for DILITHIUM
 */
export const PQ_COSE_KEY_TYPE = {
  DILITHIUM: 4, // Custom key type for DILITHIUM
};

/**
 * COSE key parameter identifiers for DILITHIUM
 */
export const PQ_COSE_KEY_PARAMS = {
  DILITHIUM_MODE: -100, // Mode parameter (2, 3, or 5)
  DILITHIUM_PK: -101, // Public key
  DILITHIUM_SK: -102, // Secret key
};

/**
 * Generate a DILITHIUM Level 2 key pair
 * @returns Promise resolving to an object containing the key pair
 */
export function generateDilithiumKeyPair(seed?: Buffer): {
  publicKey: Buffer;
  secretKey: Buffer;
} {
  if (!seed) seed = randomBytes(32);
  const keyPair = ml_dsa87.keygen(seed);
  return {
    publicKey: Buffer.from(keyPair.publicKey),
    secretKey: Buffer.from(keyPair.secretKey),
  };
}

/**
 * Sign a message using DILITHIUM Level 2
 * @param message - The message to sign
 * @param privateKey - The DILITHIUM private key
 * @returns Promise resolving to signature as Uint8Array
 */
export function signDilithium(message: Uint8Array | Buffer, secretKey: Uint8Array | Buffer): Buffer {
  return Buffer.from(ml_dsa87.sign(message, secretKey));
}

/**
 * Verify a DILITHIUM Level 2 signature
 * @param message - The original message
 * @param signature - The signature to verify
 * @param publicKey - The DILITHIUM public key
 * @returns Promise resolving to boolean indicating if signature is valid
 */
export function verifyDilithium(message: Uint8Array | Buffer, signature: Uint8Array | Buffer, publicKey: Uint8Array | Buffer): boolean {
  return ml_dsa87.verify(signature, message, publicKey);
}

/**
 * Create a COSE key representation for a DILITHIUM public key
 * @param publicKey - The DILITHIUM public key
 * @returns Map representing the COSE key
 */
export function createDilithiumCoseKey(publicKey: Uint8Array | Buffer): Map<number, any> {
  const coseKey = new Map();

  // Standard COSE key parameters
  coseKey.set(1, PQ_COSE_KEY_TYPE.DILITHIUM); // kty: Key Type
  coseKey.set(3, PQ_COSE_ALG.DILITHIUM5); // alg: Algorithm

  // DILITHIUM-specific parameters
  coseKey.set(PQ_COSE_KEY_PARAMS.DILITHIUM_MODE, 5); // Level 2
  coseKey.set(PQ_COSE_KEY_PARAMS.DILITHIUM_PK, publicKey);

  return coseKey;
}

/**
 * Get key size information for DILITHIUM
 * @returns Object with key size information
 */
export function getDilithiumKeyInfo(): {
  publicKeySize: number;
  secretKeySize: number;
  signatureSize: number;
} {
  return {
    publicKeySize: 2592, // Size in bytes for DILITHIUM2 public key
    secretKeySize: 4896, // Size in bytes for DILITHIUM5 private key
    signatureSize: 4627, // Size in bytes for DILITHIUM2 signature
  };
}
